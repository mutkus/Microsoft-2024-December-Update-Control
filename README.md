# Windows Aralık 2024 Güvenlik Yamaları Denetleme Betiği

Bu PowerShell betiği, Aralık 2024 Microsoft güvenlik bültenlerinde duyurulan belirli güvenlik açıkları (CVE-2024-49124, CVE-2024-49117, CVE-2024-49118 ve CVE-2024-49122) için gerekli KB güncellemelerinin sisteminizde yüklü olup olmadığını kontrol eder. Betik, işletim sistemi sürümünü tespit ederek hangi yamaların uygulanması gerektiğini belirlemeye çalışır ve ilk olarak tespit ettiği işletim sistemini ekrana yazar.

---

## Özellikler

- **CVE Kontrolü:**  
  Aşağıdaki CVE’ler için ilgili KB güncellemelerini kontrol eder:
  - CVE-2024-49124
  - CVE-2024-49117
  - CVE-2024-49118
  - CVE-2024-49122

- **İşletim Sistemi Tespiti:**  
  Betik, `Win32_OperatingSystem` bilgilerini kullanarak işletim sisteminizi ve sürüm numaranızı tespit eder ve ekrana:

  Tespit edilen işletim sistemi: <OS Adı>

  şeklinde yazar.

- **Güncelleme Kontrolü:**  
`Get-HotFix` komutu aracılığıyla sisteme yüklü KB güncellemelerini kontrol eder. Uygun KB bulunursa CVE'nin giderildiğine dair bilgi verir.

---

## Gereksinimler

- Windows 10, Windows 11 veya ilgili Windows Server sürümleri.
- PowerShell 5.1 veya üzeri.
- Uygun **Execution Policy** ayarları (bkz. aşağıdaki bölüm).

---

## Kullanım

1. Bu depoyu bilgisayarınıza klonlayın veya `ps1` betiğini indirin.
2. PowerShell’i **Yönetici** olarak açın.
3. Betiğin bulunduğu dizine geçin:
   powershell
 cd C:\path\to\script
4.	Gerekliyse Execution Policy Ayarı yapın.
5.	Betiği çalıştırın:
.\MS-2024-Dec-Control.ps1

Betik, işletim sisteminizi tespit edip ekrana yazacak, ardından CVE’lerin ilgili KB’lerinin kurulu olup olmadığını kontrol edecek ve sonuçları renkli olarak gösterecektir.

---

## Execution Policy Ayarı

Eğer betiği çalıştırırken şu hatayı alırsanız:

-File cannot be loaded because running scripts is disabled on this system...

Aşağıdaki yöntemlerden birini kullanabilirsiniz:

- Geçici ByPass
-   Set-ExecutionPolicy Bypass -Scope Process
.\MS-2024-Dec-Control.ps1

-Kalıcı Olarak RemoteSigned Yapmak: 
(RemoteSigned: Yerel olarak oluşturulan betiklerin çalıştırılmasına izin verir. Uzaktan indirilmiş betiklerin ise imzalı olması veya Unblock-File ile engelinin kaldırılması gerekir.)
-  Set-ExecutionPolicy RemoteSigned
.\MS-2024-Dec-Control.ps1

-Betik Engeli Kaldırma (Uzaktan İndirilen Betikler İçin):
-  Unblock-File .\MS-2024-Dec-Control.ps1

---

## Örnek Çıktı

  `Tespit edilen işletim sistemi: Microsoft Windows 10 Enterprise 10.0.19045
CVE-2024-49124 gideren KB5048652 güncelleştirmesi SİSTEMDE YÜKLÜ.
CVE-2024-49117 gideren KB5048685 güncelleştirmesi SİSTEMDE BULUNMUYOR!
CVE-2024-49118 gideren KB5048667 güncelleştirmesi SİSTEMDE YÜKLÜ.
CVE-2024-49122 gideren KB5048703 güncelleştirmesi SİSTEMDE BULUNMUYOR!` 

---

##Sorumluluk Reddi

	•	Bu betik örnek amaçlıdır. Gerçek kurulumlarda CVE-KB eşleştirmelerini Microsoft’un resmi belgelerinden doğrulamanız önerilir.
	•	İşletim sistemi sürüm tespiti basitleştirilmiş bir mantıkla yapılmıştır. Kurumsal ortamınıza uygun olarak özelleştirmeniz gerekebilir.
	•	Betiği üretim sistemlerinde kullanmadan önce test ediniz.
  
---
