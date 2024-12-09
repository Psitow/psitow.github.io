# Windows 10 Tips

ネットで見つけた情報。カテゴリは適当。

- [Windows 10 Tips](#windows-10-tips)
	- [License](#license)
	- [Drive/Storage](#drivestorage)
	- [Network](#network)
	- [Develop](#develop)
	- [Powershell](#powershell)
	- [軽量化](#軽量化)
	- [メンテナンス](#メンテナンス)
	- [Cygwin](#cygwin)
	- [Firefox](#firefox)
	- [その他](#その他)
	- [(おまけ) Windows 11](#おまけ-windows-11)

## License

+ Procy経由でライセンス認証

	```
	netsh winhttp import proxy source=ie
	or
	netsh winhttp set proxy <YOUR PROXY:PORT>
	```

+ ライセンスキー確認

	※ 参考 https://japan.zdnet.com/article/35088128/

	```
	(Get-WmiObject -Query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
	```

+ ライセンスキー確認(AD)
	```
	Get-WmiObject -Class SoftwareLicensingService | Select-Object -Property *
	```

+ ライセンスキー種類確認
	```
	slmgr /dli
	```
	<table border=1>
	<tr><td>RETAIL channel</td><td>パッケージ版</td></tr>
	<tr><td>OEM_DM channel</td><td>DSP版（またはメーカー製を問わないOEM版）</td></tr>
	<tr><td>OEM_SLP channel</td><td>OEM版（メーカー製）</td></tr>
	<tr><td>OEM_COA_NSLP channel</td><td>OEM版（メーカー製は問わず）</td></tr>
	<tr><td>VOLUME_MAK channel</td><td>VL版</td></tr>
	<tr><td>VOLUME_KMSCLIENT channel</td><td>VL版</td></tr>
	</table>

## Drive/Storage

+ リムーバブルドライブに System Volume Information を作成させない。
	```
	gpedit.msc
	```
	`ローカルコンピューターポリシー` - `コンピューターの構成` - `管理用テンプレート` - `Windowsコンポーネント` - `検索`<br>
	リムーバル ドライブ上の場所のライブラリへの追加を許可しない --> 有効

	```
	gpupdate
	```

+ c$ / admin$ 管理共有

	UACリモート設定 -- 管理者特権のトークンを構築。

	<table border=1>
	<tr><td>key</td><td>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system</td></tr>
	<tr><td rowspan=2>value</td><td>AutoShareServer = dword:1</td></tr>
	<tr><td>AutoShareWks = dword:1</td></tr>
	</table>

	修正後、net stop server / net start server<br>
	確認は、net share	(C$/IPC$/ADMIN$が表示される)

+ 送るにドライブを表示させない
	<table border=1>
	<tr><td>key</td><td>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer</td></tr>
	<tr><td>value</td><td>NoDrivesInSendToMenu = dword:1</td></tr>
	</table>

+ 最終アクセス日時の記録を無効化
	```
	fsutil behavior set disableLastAccess 1
	```

+ ドライバ署名の強制を無効にする

	Windows8では`F8`を押してもブートオプションがデフォルトで抑止されています。<br>
	コマンドプロンプトから`bcdedit /set advancedoptions on`を入力して 解除してください。

## Network

+ IPv6アドレスのデフォルトゲートウェイが取得されない

	事象が発生している・していないPCのインターフェイス設定の差異
	<table border=1>
	<tr><td></td><td>管理されたアドレス構成</td><td>その他のステートフル構成</td></tr>
	<tr><td>事象が発生しているPC</td><td>disabled</td><td>disabled</td></tr>
	<tr><td>事象が発生していないPC</td><td>enabled</td><td>enabled</td></tr>
	</table>

	Wi-Fiインタフェースの該当フラグ設定の確認、また変更方法

	1. コマンドプロンプトで「netsh interface ipv6 show interfaces」を実行
	2. 出力結果の Wi-Fi の Idx 番号を確認
	3. コマンドプロンプトで「netsh interface ipv6 show interfaces Idx 番号」を実行
	4.「管理されたアドレス構成」と「その他のステートフル構成」のフラグを確認
	5. disabled となっている場合はコマンドプロンプトで以下を実行

	```
	netsh interface ipv6 set interface Idx番号 advertise=enabled
	netsh interface ipv6 set interface Idx番号 managedaddress=enabled
	netsh interface ipv6 set interface Idx番号 otherstateful=enabled
	netsh interface ipv6 set interface Idx番号 routerdiscovery=dhcp
	netsh interface ipv6 set interface Idx番号 advertise=disabled
	netsh interface ipv6 set interface Idx番号 routerdiscovery=enabled
	```
	■コマンドプロンプト上にて、以下コマンドを実施し、PCを再起動
	```
	ipconfig /release6
	ipconfig /renew6
	```

	※ 実はこれだけ？
	```
	netsh interface ipv6 set interface Idx番号 routerdiscovery=enable
	```

+ 一時 IPv6 アドレスを消去する。
	```
	netsh interface ipv6 set privacy state=disabled
	powershell Restart-NetAdapter -Name イーサネット
	netsh interface ipv6 set privacy state=enable
	```
	※ 有効期間の設定 (default 7d)
	```
	netsh interface ipv6 set privacy maxvalidlifetime=3d
	```

+ プロキシ設定画面が表示されない

	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer<br>
	SettingsPageVisibility	STRING:"hide:proxy" <== 削除
　
+ 動的ポート数の確認

	```
	netsh int ipv4 show dynamicport tcp
	```

+ OpenSSH Server

	```
	PS C:\> Get-WindowsCapability -Online | ? Name -like "*SSH*"
	PS C:\> Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
	```
	C:\ProgramData\ssh\sshd_config

	※ コメントアウト
	```
	#Match Group administrators
	#       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
	```

+ SMBv1

	検出
	```
	Get-WindowsOptionalFeature -Online -FeatureName smb1protocol
	```
	無効化
	```
	Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
	```

+ LDAP
	<table border=1>
	<tr><td>LDP.exe:</td></tr>
	<tr><td>Search:</td></tr>
	<tr><td>Base Dn: DC=jp,DC=sony,DC=com<br>
		Filter: (&(objectclass=group)(cn=SGMO/PE/PE4/ENG2))</td></tr>
	</table>

+ 無効になった IPv6 Listen の復活
	```
	netsh http add iplisten ipaddress=::
	```

+ IPv6 net use

	```
	net use \\2001-cf8-2-405b-0-dddd-f835-9280.ipv6-literal.net\C$
	```

## Develop

+ NuGet

	```
	PS C:\> Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208
	警告: URI 'https://go.microsoft.com/fwlink/?LinkID=627338&clcid=0x409' から ''
	へダウンロードできません。
	PS C:\> [Net.ServicePointManager]::SecurityProtocol
	Ssl3, Tls
	PS C:\> [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	PS C:\> [Net.ServicePointManager]::SecurityProtocol
	Tls12
	```

+ SQL Server Express

	<table border=1>
	<tr><td>SQL Server ネットワーク構成 -- SQLEXPRESSのプロトコル -- TCP/IP [有効]</td></tr>
	<tr><td>プロパティ -- IPアドレス -- IPAll</td></tr>
	<tr><td>TCP ポート: 1433</td></tr>
	<tr><td>TCP 動的ポート: 空白</td></tr>
	</table>

	接続先名：Server name is 'hostname\SQLEXPRESS'.

+ Visual Studio 2013 認証失敗

	※ TLS 1.2 を優先に。
	+ <https://docs.microsoft.com/ja-jp/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#configure-for-strong-cryptography>
	+ <https://docs.microsoft.com/ja-jp/sharepoint/troubleshoot/administration/authentication-errors-tls12-support>

	```
	PS> Enable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" -Position 0
	PS> Enable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" -Position 1
	PS> Enable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" -Position 2
	PS> Enable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" -Position 3
	```
	Regedit
	```
	[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727]
      "SystemDefaultTlsVersions" = dword:00000001
      "SchUseStrongCrypto" = dword:00000001
	[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319]
      "SystemDefaultTlsVersions" = dword:00000001
      "SchUseStrongCrypto" = dword:00000001
	```

+ .NET Framework 3.5 有効化

	<https://docs.microsoft.com/ja-jp/troubleshoot/windows-client/application-management/dotnet-framework-35-installation-error>

	1. Windows 10 21H2 の ISO をマウント
	2. コマンドを打つ。

		```
		Dism /online /enable-feature /featurename:NetFx3 /All /Source:E:\sources\sxs /LimitAccess
		```
	3. コントロールパネルから、有効化されているか、確認。

## Powershell

+ 起動を早く。

	これを"ngen.ps1"とかに保存して実行。(管理者モード)
	```
	Set-Alias ngen @(dir (join-path ${env:\windir} "Microsoft.NET\Framework") ngen.exe -recurse | sort -descending lastwritetime)[0].fullName
	[appdomain]::currentdomain.getassemblies() | %{ngen $_.location}
	```

+ 認証付き
	```
	$cred=Get-Credential
	Enter-PSSession -ComputerName JPC00100268 -Credential $cred
	```

+ user 一覧 (SID)
	```
	Get-CimInstance -ClassName Win32_UserAccount
	```

+ Get-ADUser

	1. オプション機能追加

		RSAT: Active Directory Domain Service および ライトウェイトディレクトリサービスツール

	2. import-module ActiveDirectory

	3. Get-ADUser -Identity 1087487-Z461

	4. Get-LocalUser -Name cpcadmin
	5. Get-WmiObject Win32\_UserAccount | ? { $\_.LocalAccount -eq $true }

+ 別ユーザーで実行

	```
	Start-Process -FilePath 'Cmd.exe' -Verb RunAsUser
	```

+ パフォーマンスが悪い？

	<https://www.intellilink.co.jp/column/ms/2022/041400.aspx>
	```
	Remove-Module PSReadline
	```

+ PowerShell SQLite

	```
	Install-Module PSSQLite
	Import-Module PSSQLite

	※ Get-ExecutionPolicy -List
	※ Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine
	※ Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

	$DataSource = "C:\Users\アカウント名\AppData\Local\Temp\bc3902d8132f43e3ae086a009979fa88.db"
	$Query = "select * from sqlite_master"
	Invoke-SqliteQuery -Query $Query -DataSource $DataSource
	```

## 軽量化

+ WWindows Defender 無効化

	<table border=1>
	<tr><td>key</td><td>HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender</td></tr>
	<tr><td>value</td><td>DisableAntiSpyware = dword:1</td></tr>
	</table>

+ タスク無効化

	<table border=1>
	<tr><td rowspan=3>Application Experience</td><td>AitAgent</td></tr>
	<tr><td>Microsoft Compatibility Appraiser</td></tr>
	<tr><td>ProgramDataUpdater</td></tr>
	<tr><td>Autochk</td><td>Proxy</td></tr>
	<tr><td>Customer Experience Improvement Program</td><td>*</td></tr>
	<tr><td>Defrag</td><td>ScheduledDefrag</td></tr>
	<tr><td>DiskDiagnostic</td><td>Microsoft-Windows-DiskDiagnosticDataColl</td></tr>
	<tr><td>DiskFootPrint</td><td>Diagnostics</td></tr>
	<tr><td>Miantnance</td><td>WinSAT</td></tr>
	</table>

+ IME

	予測入力を無効

+ 機能無効化

	<table border=1>
	<tr><td>Remote Differential Compression API サポート</td></tr>
	<tr><td>Windows プロセス アクティブ化サービス</td></tr>
	<tr><td>ワーク フォルダー クライアント</td></tr>
	</table>

+ SXS Assembly の整理

	```
	dism /Online /CLeanup-Image /AnalyzeComponentStore
	dism /Online /CLeanup-Image /StartComponentCleanup
	```

## メンテナンス

+ Windows image のリストアと検査

	```
	dism /online /cleanup-image /restorehealth
	sfc /scannow
	```

+ windows update 一覧

	```
	Get-WmiObject win32_quickfixengineering >wupdate.log
	```
	```
	function Get-InstalledKB
	{
	    $session = New-Object -ComObject Microsoft.Update.Session
	    $searcher = $session.CreateUpdateSearcher()
	    $results = $searcher.QueryHistory(0, $searcher.GetTotalHistoryCount())
	    $results|
	        where Title -ne $null |
	        select @(
	            @{L="HotFixId";E={$_.Title -replace '^.*(KB\d+).*$','$1'}},
	            "Date",
	            "Title",
	            "Description"
	        )
	}
	```
	```
	Get-InstalledKB | where HotFixId -eq KB3194798
	```

+ Task Bar アイコンの(もう一つの)追加場所 (Quick Launch)

	AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar

+ Fix Event ID 642 ESENT error on Windows 10

	```
	Dism /Online /Cleanup-Image /StartComponentCleanup
	Dism /Online /Cleanup-Image /RestoreHealth
	SFC /scannow
	```

+ Windows 8.1 WPF Clash -- KB4601048
	+ windows 10 1909 -- KB4601556 で修正
	+ Windows 10 2004/20H2 -- KB4601554 で修正

		※ powershell Get-HotFix

+ x86/Win32 application ('Access'を含む) を表示 (uninstall情報も)
	```
	wmic path win32_product where (caption like '%Access%')
	wmic path Win32_Product get Caption,InstallSource,PackageCache,PackageCode,PackageName
	Get-WmiObject Win32_Product | Select-Object Caption,InstallSource,PackageCache,PackageCode,PackageName
	```

+ スマホ同期、Xbox Game Bar 削除
	```
	Get-AppxPackage Microsoft.YourPhone -AllUsers | Remove-AppxPackage
	Get-AppxPackage Microsoft.XboxGamingOverlay | Remove-AppxPackage
	```

+ 「高パフォーマンス」を追加
	```
	powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
	```

+ OneDriveに移動を無効にする。
	```
	reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}" /t REG_SZ /f
	```
	サインインしなおし。

+ Office を以前のバージョンに戻す。

	一行ずつ貼り付けて、［Enter］キーを押す
	```
	cd %programfiles%\Common Files\Microsoft Shared\ClickToRun
	officec2rclient.exe /update user updatetoversion=16.0.15225.20288
	```

+ シンボリックリンクをリモートから参照

	※ 参照する側で設定。
	```
	fsutil behavior set symlinkevaluation r2l:1 r2r:1
	```
	確認。
	```
	fsutil behavior query symlinkevaluation
	```

+ 電卓再インストール
	```
	Get-AppxPackage -AllUsers *windowscalculator* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppxManifest.xml"}
	```

+ ActiveDirectory (AD / jp.hogehoge.com) に参加できなくなった。

	※ 2022/10月のMicrosoftセキュリティパッチの影響

	1. gpupdate /force

	2. (ダメな場合)<br>
		HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA
		NetJoinLegacyAccountReuse (DWORD) ==> 1

+ HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices 削減
	```
	mountvol /R
	```

+ Windows Hypervisor Platform の起動確認

	bcdedit /enum {current}
	```
	C:\windows\system32>bcdedit /enum {current}

	Windows ブート ローダー
	--------------------------------
	identifier              {current}
	device                  partition=C:
	path                    \windows\system32\winload.efi
	description             Windows 10
	locale                  ja-JP
	inherit                 {bootloadersettings}
	recoverysequence        {7b259526-1066-11ee-94b6-a6e6b363712d}
	displaymessageoverride  Recovery
	recoveryenabled         Yes
	isolatedcontext         Yes
	allowedinmemorysettings 0x15000075
	osdevice                partition=C:
	systemroot              \windows
	resumeobject            {7b259524-1066-11ee-94b6-a6e6b363712d}
	nx                      OptIn
	bootmenupolicy          Standard
	hypervisorlaunchtype    Auto <== これ
	```

+ 設定画面上部のバナーを消す
	<table border=1>
	<tr><td colspan=2>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\4\4095660171</td></tr>
	<tr><td>EnabledState</td><td>REG_DWORD 1</td></tr>
	<tr><td>EnabledStateOptions</td><td>REG_DWORD 1</td></tr>
	</table>

+ プロセス起動コマンドライン
	```
	wmic process get processid,name,commandline /format:csv >C:\Temp\procs.csv
	```

+ タスク一覧(詳細)
	```
	schtasks /query /V /FO CSV >C:\Temp\tasks.csv
	```

+ プログラム一覧(レジストリ)

	```
	Get-ChildItem -Path(
		'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstal') |
	% { Get-ItemProperty $_.PsPath } | Select-Object -Property DisplayName,DisplayVersion
	```

+ プログラム一覧(WMI)

	```
	wmic product list
	Get-WmiObject Win32_Product
	```

+ WSL 再インストール

	<https://aka.ms/wslstorepage>


+ WindowsRE
	```
	sfc /scannow /offbootdir=C:\ /offwindir=C:\Windows
	dism /Image:C:\ /CLeanup-Image /scanhelth
	```
	※ network 有効化
	```
	wpeutil InitializeNetwork
	```

## Cygwin

+ cygwin unzip 日本語ファイル名文字化け

	-Ocp932 で、cp932 でファイル名を展開
	```
	unzip -Ocp932 hogehoge.zip
	```

+ Cygwin / Mintty / Wsltty 日本語入力で確定`Enter`すると_A になってしまう。

	`Options` -> `Keys` -> "ESC/Enter reset IME to alphanumeric" のチェックをはずず。


## Firefox

+ Firefox 統合Windows認証設定（SPNEGO認証）
	```
	about:config
	network.negotiate-auth.trusted-uris
	https://autologon.microsoftazuread-sso.com	
	```

+ アドレスバーの検索機能やめ (古い、効果なし？)
	```
	browser.fixup.alternate.enabled	--> false
	keyword.enabled --> false	
	```
+ ロケーションバーでかくなるを禁止 (古い、効果なし？)
	```
	browser.urlbar.megabar --> false
	```
+ ロケーションバーに移動しちまうの禁止したい。

	autoFill の関連でしょうか？

+ Firefox(89) Proton UI やめたい。

	※ 以下をfalse (古い、効果なし？)
	```
    browser.proton.contextmenus.enabled
    browser.proton.doorhangers.enabled
    browser.proton.enabled (※ これ false だと、設定画面のチェックボックス判別不能。なんだそりゃ？)
    browser.proton.modals.enabled
	```

	Firefox89から動作が変りました。

	<https://support.mozilla.org/ja/kb/about-config-editor-firefox>

	設定エディター (about:config ページ)を開いて、以下を入力し、trueとなってるのをfalseに変更することでFirefox88までと同じ動作になります。
	```
	browser.newtabpage.activity-stream.improvesearch.handoffToAwesomebar
	```

## その他

+ ??

	`管理用テンプレート` - `ネットワーク/Windows 接続マネージャー`<br>
	ドメイン認証されたネットワークに接続しているときに非ドメイン ネットワークへの接続を禁止する ==> 無効 (が、効くかも)

+ Windows オーディオ デバイス グラフ アイソレーション

	+ ./WinSxS/amd64\_microsoft-windows-audio-audiocore\_31bf3856ad364e35\_6.3.9600.17415\_none\_67aabf0db85d32d6/audiodg.exe
	+ ./WinSxS/amd64\_microsoft-windows-audio-audiocore\_31bf3856ad364e35\_6.3.9600.17893\_none\_675246b1b89fd44c/audiodg.exe

## (おまけ) Windows 11

+ 画面上部のバー(スナップ)

	`システム` -> `マルチタスク`<br>
	ウィンドウのスナップ : オフ

+ 右クリックメニューを旧仕様に。
	<table border=1>
	<tr><td>HKEY_CURRENT_USER\Software\Classes\CLSID</tr></tr>
	<tr><td>新規キー : {86ca1aa0-34aa-4e8b-a509-50c905bae2a2}</tr></tr>
	<tr><td>新規キー : InprocServer32</tr></tr>
	<tr><td>(規定) -- 空</tr></tr>
	</table>

+ スタートメニューを Windows 10 に (※ 機能しない)
	<table border=1>
	<tr><td>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced</tr></tr>
	<tr><td>Start_ShowClassicMode : 0 --> 1</td></tr>
	</table>

+ 角丸 (※ これも効かない)
	<table border=1>
	<tr><td>コンピューター\HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM</td></tr>
	<tr><td>UseWindowFrameStagingBuffer DWORD 0</td></tr>
	</table>

+ Windows Web Experience pack

	削除
	```
	winget uninstall "windows web experience pack" or
		  Get-AppxPackage -Name MicrosoftWindows.Client.WebExperience | Remove-AppxPackage -Verbose
	```
	復帰

	<https://www.microsoft.com/ja-jp/p/app/9mssgkg348sp>

+ 明るさ・輝度の自動調整オフ

	`システム`->`ディスプレイ`-> `コンテンツに基づいて明るさを変更する`->オフ

