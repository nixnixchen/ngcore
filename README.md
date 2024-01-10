

Description:
ngcore try to get rid of the blocking perioid of gcore. ngcore use clone to create a copy of the target process, then trigger a signal to create the dump file. The whole work is done by attaching to the target. Users do not need to regenerate executable files of the target. 


Usage:
./bin/ngcore -p [pid]

TODO:
1. get rid of zombie processes produced by killing puppet process

References:
[Google Coredumper]  https://github.com/anatol/google-coredumper
