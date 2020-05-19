/*
 * (c) 2018-2019 Ionic Security Inc. By using this code, I agree to the Terms & Conditions
 * (https://dev.ionic.com/use.html) and the Privacy Policy (https://www.ionic.com/privacy-notice/).
 */

package com.ionic.cloudstorage.icct;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.DefaultAwsRegionProviderChain;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3URI;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import com.ionic.cloudstorage.awss3.IonicS3EncryptionClient;
import com.ionic.cloudstorage.awss3.IonicS3EncryptionClientBuilder;
import com.ionic.cloudstorage.azurestorage.IonicKeyResolverFactory;
import com.ionic.cloudstorage.gcs.GoogleIonicStorage;
import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.data.MetadataMap;
import com.ionic.sdk.agent.key.KeyAttributesMap;
import com.ionic.sdk.agent.request.createkey.CreateKeysRequest;
import com.ionic.sdk.agent.request.getkey.GetKeysResponse;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.error.IonicException;
import com.microsoft.azure.keyvault.cryptography.SymmetricKey;
import com.microsoft.azure.storage.blob.BlobEncryptionPolicy;
import com.microsoft.azure.storage.blob.BlobRequestOptions;
import com.microsoft.azure.storage.blob.CloudBlockBlob;
import com.microsoft.azure.storage.blob.CloudBlobClient;
import com.microsoft.azure.storage.blob.CloudBlobContainer;
import com.microsoft.azure.storage.CloudStorageAccount;
import com.microsoft.azure.storage.StorageCredentials;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.lang.NullPointerException;
import java.net.URISyntaxException;
import java.net.ConnectException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class IonicCloudCopy {
    public static void usage() {
        System.out.println("<source> <destination> [-a 'attribute1:val1:val2,attribute2:val3'] ");
        System.out.println(
                "  Data from the source is copied to the destination and protected with IDTCS if the destination is remote.");
        System.out.println("Sources:");
        System.out.println("  file/system/path");
        System.out.println("  string:'Text of choice.'");
        System.out.println("  s3://s3bucket/path/to/object");
        System.out.println("  gs://gcsbucket/path/to/object");
        System.out.println("  az:azureContainer/path/to/blob");
        System.out.println("Destinations:");
        System.out.println("  file/system/path");
        System.out.println("  stdout:");
        System.out.println("  s3://s3bucket/path/to/object");
        System.out.println("  gs://gcsbucket/path/to/object");
        System.out.println("  az:azureContainer/path/to/blob");
        System.out.println("-a only valid for local or string sources");
        System.out.println("Single Argument Commands:");
        System.out.println("  version");
        System.out.println("  config");
        System.exit(0);
    }

    enum LocationType {
        GCS, // Source, Destination
        S3, // Source, Destination
        AZURE, // Source, Destination
        LOCAL, // Source, Destination
        STRING, // Source
        STDOUT; // Destination
    }

    static class Location {
        public LocationType locType;
        public String bucket;
        public String object;
        public String data;
        public File file;
        public String region;
    }

    private static String gProfilePath =
            System.getProperty("user.home") + "/.ionicsecurity/profiles.pt";

    /* This code uses a PlaintextPersistor for demonstration purposes. For
     * production code it is recomended to use a more secure Persistor type.
     */


    private static Agent getAgentUnchecked() throws IonicException {
        if (gIonicAgent == null) {
            DeviceProfilePersistorPlainText persistor = new DeviceProfilePersistorPlainText();
            persistor.setFilePath(gProfilePath);
            Agent agent = new Agent();
            agent.initialize(persistor);
            agent.setMetadata(getMetadataMap());
            gIonicAgent = agent;
        }
        return gIonicAgent;
    }

    private static Agent getAgent() {
        try {
            return getAgentUnchecked();
        } catch (IonicException e) {
            System.err.println("Error loading persistor: " + e.getMessage());
            System.exit(1);
        }
        return null;
    }

    private static KeyAttributesMap attributes;
    private static Agent gIonicAgent;
    private static DeviceProfilePersistorPlainText gPersistor;
    private static IonicS3EncryptionClient gs3;
    private static GoogleIonicStorage gStorage;
    private static IonicKeyResolverFactory gIonicAzureResolver;
    private static CloudBlobClient gAzureClient;

    public static void main(String[] args) {

        if (args.length == 0) {
            usage();
        }
        if (args.length == 1) {
            if (args[0].equals("version")) {
                System.out.println(Version.getFullVersion());
                System.exit(0);
            } else if (args[0].equals("config")) {
                System.exit(configurationCheck());
            }
            usage();
        }

        Location source = sourceFromArg(args[0]);
        Location destination = destinationFromArg(args[1]);

        // Parse attributes from arguments if Source is a String or local file
        if (args.length >= 3 && ((source.locType == LocationType.STRING)
                || (source.locType == LocationType.LOCAL))) {
            if (!"-a".equals(args[2]) || args.length < 4) {
                usage();
            }
            attributes = parseAttributes(args[3]);
        } else {
            attributes = new KeyAttributesMap();
        }

        IonicKeyBytesPair pair = dataFromSource(source);
        if (pair.getKey() != null) {
            // Copy Ionic Attributes from source object
            attributes = pair.getKey().getAttributesMap();
            // Add source's Ionic KeyID as origin
            attributes.put("ionic-saved-from",
                    new ArrayList<String>(Arrays.asList(pair.getKey().getId())));
        }

        writeToDestination(destination, pair.getByteArray(), attributes);

        System.exit(0);
    }

    public static Location sourceFromArg(String source) {
        if (source.startsWith("string:")) {
            Location ret = new Location();
            ret.locType = LocationType.STRING;
            ret.data = source.substring(7, source.length());
            return ret;
        } else if (source.startsWith("s3://")) {
            return S3Location(source);
        } else if (source.startsWith("gs://")) {
            return GSLocation(source);
        } else if (source.startsWith("az:")) {
            return AZLocation(source);
        } else {
            Location ret = new Location();
            ret.locType = LocationType.LOCAL;
            File file = new File(source);
            if (!file.exists()) {
                System.err.println(source + " not found.");
                System.exit(1);
            }
            ret.file = file;
            return ret;
        }
    }

    public static Location destinationFromArg(String destination) {
        if (destination.equals("stdout:")) {
            Location ret = new Location();
            ret.locType = LocationType.STDOUT;
            return ret;
        } else if (destination.startsWith("s3://")) {
            return S3Location(destination);
        } else if (destination.startsWith("gs://")) {
            return GSLocation(destination);
        } else if (destination.startsWith("az:")) {
            return AZLocation(destination);
        } else {
            Location ret = new Location();
            ret.locType = LocationType.LOCAL;
            File file = new File(destination);
            if (file.exists()) {
                file.delete();
            }
            ret.file = file;
            return ret;
        }
    }

    // Return object for storing Key and Plaintext pair
    public static class IonicKeyBytesPair {
        private GetKeysResponse.Key key;
        private byte[] byteArray;

        private IonicKeyBytesPair(GetKeysResponse.Key key, byte[] byteArray) {
            this.key = key;
            this.byteArray = byteArray;
        }

        public GetKeysResponse.Key getKey() {
            return this.key;
        }

        public byte[] getByteArray() {
            return this.byteArray;
        }
    }

    public static IonicKeyBytesPair dataFromSource(Location source) {
        if (source.locType == LocationType.STRING) {
            return new IonicKeyBytesPair(null, source.data.getBytes());
        } else if (source.locType == LocationType.S3) {
            if (!getS3().doesObjectExist(source.bucket, source.object)) {
                System.err.println(
                        "Key " + source.object + " does not exist for bucket " + source.bucket);
                System.exit(1);
            }
            try {
                // If a region was specified in the uri set for IonicS3EncryptionClient
                Region defaultRegion = null;
                if (source.region != null) {
                    defaultRegion = RegionUtils.getRegion(getS3().getRegionName());
                    getS3().setRegion(RegionUtils.getRegion(source.region));
                }
                IonicS3EncryptionClient.IonicKeyS3ObjectPair pair =
                        getS3().getObjectAndKey(source.bucket, source.object);
                IonicKeyBytesPair ret = new IonicKeyBytesPair(pair.getKey(),
                        IOUtils.toByteArray(pair.getS3Object().getObjectContent()));
                // Reset the region to the default if one was specified by the uri
                if (defaultRegion != null) {
                    getS3().setRegion(defaultRegion);
                }
                return ret;
            } catch (AmazonS3Exception|IOException e) {
                System.err.println(e.getLocalizedMessage());
                System.exit(1);
            }
        } else if (source.locType == LocationType.GCS) {
            try {
                GoogleIonicStorage.IonicKeyBytesPair pair =
                        getGCS().readAllBytesAndKey(source.bucket, source.object);
                return new IonicKeyBytesPair(pair.getKey(), pair.getByteArray());
            } catch (com.google.cloud.storage.StorageException e) {
                System.err.println(e.getLocalizedMessage());
                System.exit(1);
            }
        } else if (source.locType == LocationType.AZURE) {
            try {
                CloudBlobContainer container = getAzureClient().getContainerReference(source.bucket);
                CloudBlockBlob blob = container.getBlockBlobReference(source.object);
                IonicKeyResolverFactory.IonicKeyResolver keyResolver =
                        getIonicKeyResolverFactory().createKeyResolver();
                BlobEncryptionPolicy downloadPolicy = new BlobEncryptionPolicy(null, keyResolver);
                BlobRequestOptions options = new BlobRequestOptions();
                options.setEncryptionPolicy(downloadPolicy);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                blob.download(byteArrayOutputStream, null, options, null);
                GetKeysResponse.Key ionicKey = keyResolver.getKey();
                return new IonicKeyBytesPair(ionicKey, byteArrayOutputStream.toByteArray());
            } catch (com.microsoft.azure.storage.StorageException|URISyntaxException e) {
                System.err.println(e.getLocalizedMessage());
                System.exit(1);
            }
        } else if (source.locType == LocationType.LOCAL) {
            try {
                return new IonicKeyBytesPair(null, FileUtils.readFileToByteArray(source.file));
            } catch (IOException e) {
                System.err.println("Failure reading from File: " + source.file.getAbsolutePath());
                System.exit(1);
            }
        }
        return null;
    }

    public static void writeToDestination(Location destination, byte[] data,
            KeyAttributesMap attributes) {
        if (destination.locType == LocationType.STDOUT) {
            try {
                System.out.write(data);
                System.out.println("");
            } catch (IOException e) {
                System.err.println("Failure writing to stdout");
                System.exit(1);
            }
        } else if (destination.locType == LocationType.S3) {
            InputStream is = new ByteArrayInputStream(data);
            ObjectMetadata s3ObjectMetadata = new ObjectMetadata();
            s3ObjectMetadata.setContentLength(data.length);
            // If a region was specified in the uri set for IonicS3EncryptionClient
            Region defaultRegion = null;
            if (destination.region != null) {
                defaultRegion = RegionUtils.getRegion(getS3().getRegionName());
                getS3().setRegion(RegionUtils.getRegion(destination.region));
            }
            getS3().putObject(destination.bucket, destination.object, is, s3ObjectMetadata,
                    new CreateKeysRequest.Key("", 1, attributes));
            // Reset the region to the default if one was specified by the uri
            if (defaultRegion != null) {
                getS3().setRegion(defaultRegion);
            }
        } else if (destination.locType == LocationType.GCS) {
            BlobInfo blobInfo =
                    BlobInfo.newBuilder(BlobId.of(destination.bucket, destination.object))
                            .setContentType("application/octet-stream").build();
            getGCS().create(blobInfo, data, new CreateKeysRequest.Key("", 1, attributes));
        } else if (destination.locType == LocationType.AZURE) {
            try {
                CloudBlobContainer container = getAzureClient().getContainerReference(destination.bucket);
                CloudBlockBlob blob = container.getBlockBlobReference(destination.object);
                BlobEncryptionPolicy policy = new BlobEncryptionPolicy(getIonicKeyResolverFactory().
                  create(new CreateKeysRequest.Key("", 1, attributes)), null);
                BlobRequestOptions options = new BlobRequestOptions();
                options.setEncryptionPolicy(policy);
                blob.uploadFromByteArray(data, 0, data.length, null, options, null);
            } catch (com.microsoft.azure.storage.StorageException|IonicException|IOException|URISyntaxException e) {
                System.err.println(e.getLocalizedMessage());
                System.exit(1);
            }
        } else if (destination.locType == LocationType.LOCAL) {
            try {
                FileUtils.writeByteArrayToFile(destination.file, data);
            } catch (IOException e) {
                System.err
                        .println("Failure writing to File: " + destination.file.getAbsolutePath());
                System.exit(1);
            }
        }
    }

    public static Location S3Location(String uri) {
        if (checkAWSCredentialsConfiguration() != null || checkAWSRegionConfiguration() != null) {
            System.out.println("Service S3 is not configured. Run command config for details.");
            System.exit(1);
        }
        Location ret = new Location();
        ret.locType = LocationType.S3;
        AmazonS3URI as3Uri = new AmazonS3URI(uri);
        if (!getS3().doesBucketExist(as3Uri.getBucket())) {
            System.err.println("Bucket " + as3Uri.getBucket()
                    + " does not exist or user lacks adequate permission access it.");
            System.exit(1);
        }
        ret.bucket = as3Uri.getBucket();
        ret.object = as3Uri.getKey();
        ret.region = as3Uri.getRegion();
        return ret;
    }

    public static Location GSLocation(String uri) {
        if (checkGoogleCredentials() != null) {
            System.out.println(
                    "Service Google Storage is not configured. Run command config for details.");
            System.exit(1);
        }
        Location ret = new Location();
        ret.locType = LocationType.GCS;
        String sub = uri.substring(5, uri.length());
        String[] component = sub.split("/", 2);
        if (component.length != 2) {
            System.err.println("Invalid GCS uri: " + uri);
            System.exit(1);
        }
        if (getGCS().get(component[0], Storage.BucketGetOption.fields()) == null) {
            System.err.println("Bucket " + component[0]
                    + " does not exist or user lacks adequate permission access it.");
            System.exit(1);
        }
        ret.bucket = component[0];
        ret.object = component[1];
        return ret;
    }

    public static Location AZLocation(String uri) {
        if (checkAzureCredentials() != null) {
            System.out.println(
            "Service Azure Storage is not configured. Run command config for details.");
            System.exit(1);
        }
        Location ret = new Location();
        ret.locType = LocationType.AZURE;
        String sub = uri.substring(3, uri.length());
        String[] component = sub.split("/", 2);
        if (component.length != 2) {
            System.err.println("Invalid Azure uri: " + uri +
                "\n Uri must contain a Container followed by a '/' followed by a Blob name.");
            System.exit(1);
        }
        try {
            getAzureClient().getContainerReference(component[0]);
        } catch (com.microsoft.azure.storage.StorageException|URISyntaxException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        ret.bucket = component[0];
        ret.object = component[1];
        return ret;
    }

    public static KeyAttributesMap parseAttributes(String str) {
        KeyAttributesMap ret = new KeyAttributesMap();
        String[] pairs = str.split(",");
        for (String pair : pairs) {
            String[] tuples = pair.split(":");
            ArrayList<String> values = new ArrayList<String>();
            for (int i = 1; i < tuples.length; i++) {
                values.add(tuples[i]);
            }
            ret.put(tuples[0], values);
        }
        return ret;
    }

    public static void printMap(KeyAttributesMap map) {
        map.forEach((k, v) -> {
            System.out.print((k));
            v.forEach((i) -> System.out.print(":" + i));
            System.out.println("");
        });
    }

    // Metadata attached to Ionic interactions
    public static MetadataMap getMetadataMap() {
        MetadataMap mApplicationMetadata = new MetadataMap();
        mApplicationMetadata.set("ionic-application-name", "IDTCS-demo-application");
        mApplicationMetadata.set("ionic-application-version", Version.getFullVersion());
        mApplicationMetadata.set("ionic-client-type", "Ionic Data Trust for Cloud Services");

        return mApplicationMetadata;
    }

    // Client setup methods

    public static GoogleIonicStorage getGCS() {
        if (gStorage == null) {
            gStorage = new GoogleIonicStorage(getAgent(),StorageOptions.getDefaultInstance()
                    .getService());
        }
        return gStorage;
    }

    public static IonicS3EncryptionClient getS3() {
        if (gs3 == null) {
            gs3 = (IonicS3EncryptionClient) IonicS3EncryptionClientBuilder.standard()
                    .withIonicAgent(getAgent()).buildIonic();
        }
        return gs3;
    }

    private static CloudBlobClient getAzureClient() {
        if (gAzureClient == null) {
            try {
                CloudStorageAccount account = new CloudStorageAccount(getAzureStorageCredentials(), true);
                gAzureClient = account.createCloudBlobClient();
            } catch (Exception e) {
                System.err.println(e.getMessage());
                System.exit(1);
            }
        }
        return gAzureClient;
    }

    private static IonicKeyResolverFactory getIonicKeyResolverFactory()  {
        if (gIonicAzureResolver == null) {
            gIonicAzureResolver = new IonicKeyResolverFactory(getAgent());
        }
        return gIonicAzureResolver;
    }

    // Configuration Checks


    public static String checkIonicConfiguration() {
        try {
            Agent agent = getAgentUnchecked();
            agent.getKey("").getFirstKey();
        } catch (IonicException e) {
            if (e.getReturnCode() == 40024) {
                return null;
            } else if (e.getReturnCode() == 40021) {
                return "Issue loading persistor at: " + gProfilePath;
            } else {
                return e.getMessage();
            }
        }
        return null;
    }

    public static String checkAWSCredentialsConfiguration() {
        try {
            DefaultAWSCredentialsProviderChain.getInstance().getCredentials();
        } catch (SdkClientException e) {
            return e.getLocalizedMessage();
        }
        return null;
    }

    public static String checkAWSRegionConfiguration() {
        try {
            new DefaultAwsRegionProviderChain().getRegion();
        } catch (SdkClientException e) {
            return e.getLocalizedMessage();
        }
        return null;
    }

    public static String checkGoogleCredentials() {
        try {
            GoogleCredential.getApplicationDefault();
        } catch (ConnectException e) {
            return e.getLocalizedMessage();
        } catch (IOException e) {
            return e.getLocalizedMessage();
        }
        return null;
    }

    public static StorageCredentials getAzureStorageCredentials() throws
    InvalidKeyException, SecurityException, IllegalArgumentException,
    com.microsoft.azure.storage.StorageException {
        String account = System.getenv("AZURE_STORAGE_ACCOUNT");
        String key = System.getenv("AZURE_STORAGE_ACCESS_KEY");
        if (account == null ) {
            throw new IllegalArgumentException("AZURE_STORAGE_ACCOUNT is not present in environment.");
        }
        if (key == null) {
            throw new IllegalArgumentException("AZURE_STORAGE_ACCESS_KEY is not present in environment.");
        }
        String creds = "AccountName=" + account + ";" + "AccountKey=" + key;
        return StorageCredentials.tryParseCredentials(creds);
    }

    public static String checkAzureCredentials() {
        try {
            getAzureStorageCredentials();
        } catch (Exception e) {
            return e.getLocalizedMessage();
        }
        return null;
    }

    public static int configurationCheck() {
        int exitCode = 0;

        String ionicCheckResult = checkIonicConfiguration();
        String awsCredsCheckResult = checkAWSCredentialsConfiguration();
        String awsRegionCheckResult = checkAWSRegionConfiguration();
        String googleCheckResult = checkGoogleCredentials();
        String azureCheckResult = checkAzureCredentials();

        if (ionicCheckResult != null) {
            System.out.println("Ionic Configuration Status: ERROR:");
            System.out.println('\t' + ionicCheckResult + '\n');
            exitCode = 1;
        } else {
            System.out.println("Ionic Configuration Status: CONFIGURED");
        }

        if (awsCredsCheckResult != null) {
            System.out.println("AWS Credential Configuration: ERROR:");
            System.out.println('\t' + awsCredsCheckResult + '\n');
            exitCode = 1;
        } else {
            System.out.println("AWS Credential Configuration: CONFIGURED");
        }

        if (awsRegionCheckResult != null) {
            System.out.println("AWS Region Configuration: ERROR:");
            System.out.println('\t' + awsRegionCheckResult + '\n');
            exitCode = 1;
        } else {
            System.out.println("AWS Region Configuration: CONFIGURED");
        }

        if (googleCheckResult != null) {
            System.out.println("Google Credential Configuration: ERROR:");
            System.out.println('\t' + googleCheckResult + '\n');
            exitCode = 1;
        } else {
            System.out.println("Google Credential Configuration: CONFIGURED");
        }

        if (azureCheckResult != null) {
            System.out.println("Azure Credential Configuration: ERROR:");
            System.out.println('\t' + azureCheckResult + '\n');
            exitCode = 1;
        } else {
            System.out.println("Azure Credential Configuration: CONFIGURED");
        }

        return exitCode;
    }

}
