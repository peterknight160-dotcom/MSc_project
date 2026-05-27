This root top/level directory for my dissertation on PQC for vehicles

crates  - contains the common functions

target is for the executables - the Docker images will pick up there images from here. 
  It has two subdirectores - x86_64 for PC based executables and arm8 for Raspberry Pi executables

  While target exists in the directory structure, it is not uploaded to GitHub



apps    - contains the apps - dongle, control & receiver


The directory ../cargo is used for the cache - so the imported crates are not repeatedly downloaded.









