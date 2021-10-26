set maxFileSize=0
set filemode="single"

if [%1] == [] (
 GOTO starttrace   
)

if "%1" == "-m" (
    set filemode="circular"
    set maxFileSize=%2
)

:starttrace
    cmd /c """netsh trace start globallevel=6 provider={564368D6-577B-4af5-AD84-1C54464848E6} provider={0c885e0d-6eb6-476c-a048-2457eed3a5c1} provider={80CE50DE-D264-4581-950D-ABADEEE0D340} provider={D0E4BC17-34C7-43fc-9A72-D89A59D6979A} provider={93f693dc-9163-4dee-af64-d855218af242} provider={A6F32731-9A38-4159-A220-3D9B7FC5FE5D} provider={6C28C7E5-331B-4437-9C69-5352A2F7F296} provider={1F387CBC-6818-4530-9DB6-5F1058CD7E86} keywords=0xFFDFFFFB provider={67DC0D66-3695-47c0-9642-33F76F7BD7AD} keywords=0xFFFFFFDD report=di capture=no tracefile=c:\server.etl filemode=%filemode% maxsize=%maxFileSize% overwrite=yes persistent=yes"""

