#Ionic Cloud Copy Tool demo

## Building the tool
### Requirements:
Java 7 or later
Maven 3 or later

## Building the jar
From the project root run `mvn package`

# Using the tool

## Ionic Requirements

### Enroll an Ionic Persistor

Either use a plaintext persistor located at $HOME/.ionicsecurity/profiles.pt or edit the code on lines 90-103 to use another persistor class. Guides on persistor enrollment can be found [here](https://dev.ionic.com/getting-started/create-ionic-profile) and code examples of different persistors can be found [here](https://github.com/IonicDev/samples/tree/master/java).

## AWS Setup

### Set up AWS ENV variables

`AWS_ACCESS_KEY_ID=your_access_key_id`
`AWS_SECRET_ACCESS_KEY=your_secret_access_key`
`AWS_REGION=your_default_amazon_region`

Details on setting up and configuring Ionic for AWS S3 can be found at [here](https://dev.ionic.com/integrations/aws-s3/setup).

## GCS Setup

### Set up GCS ENV variables

`GOOGLE_APPLICATION_CREDENTIALS=path/to/a/google/serviceAccount.json`

Details on setting up and configuring Ionic for GCS can be found [here](https://dev.ionic.com/integrations/ipcs-gcs/setup).

## Running the tool

Once the tool has been built it can be called using the icct.sh or icct.bat script (referred to as icct for the rest of this document).

## Commands

### Secure Cloud Copy

Running the command `icct <source> <destination>` will copy the data specified in the source to the destination. If the destination is a remote location then the data will be protected by encryption en route. If the source is a remote location the data will be decrypted en route. If both the source and the destination are remote then the data will be decrypted and then reprotected en route preserving any attributes associated with the underlying Ionic key.

#### Local Sources

A file from the local file system can be used as a source by providing a path to the file for the `<source>` argument.
A UTF8 encoded string can be used as a source by using the following syntax `string:'Your string here'` for the source argument.

Additionally local sources can optionally include attributes to be set on the Ionic Key protecting the data by using the `-a` flag. Ex: `-a 'attribute1:val1:val2,attribute2:val3'`.

#### Local Destinations

The data from a source can be written to the local file system by providing a path to the file to write to for the `<destination>` argument. If the file already exists it will be overwritten.
The data from the source can be displayed via standard out by using `stdout:` as the argument for the `<destination>`.

#### Remote Sources and Destinations

An AWS S3 object can be used as either a `<source>` or `<destination>` by using the following syntax: `s3://s3bucket/path/to/object/`.

A GCS object can be used as either a `<source>` or a `<destination>` by using the following syntax: `gs://gcsbucket/path/to/object`.

### Configuration check

Running the command `icct config` will check and display the configuration status of the dependent services.

### Version

Running the command `icct version` will display the version of the tool.
