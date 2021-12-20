set ida_path=D:\IDA7.5\idat64

::set script_path="./graph.py"
set script_path="./Decompiler.py"

::set target="C:\Users\will\Desktop\strip_bin\test"
::set target="C:\Users\will\Desktop\strip_bin\n2n\edge-s"
::set target="C:\Users\will\Desktop\strip_bin\mozjpeg\libturbojpeg.so.0.2.0-s"
::set target="C:\Users\will\Desktop\strip_bin\libpng\libpng16.so-s"
::set target="C:\Users\will\Desktop\strip_bin\ly\ly-s"
set target="C:\Users\will\Desktop\strip_bin\lz4\lz4-s"
::set target="C:\Users\will\Desktop\test"

set log_file="./log.txt"

%ida_path% -A -c -S%script_path% -L%log_file% %target% 