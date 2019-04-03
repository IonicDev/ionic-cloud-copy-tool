for %%i in (target\IonicCloudCopyTool-*.jar) do set jar_path= %%i
java -jar %jar_path% %*