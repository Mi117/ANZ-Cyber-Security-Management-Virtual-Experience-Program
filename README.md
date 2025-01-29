# ANZ-Cyber-Security-Management-Virtual-Experience-Program
Simulation focussed on identifying cybersecurity threats (email phishing attemps) and analyse and investigate suspicious Packet traffic utilizing open-sourced software (Wireshark)

OBJECTIVE

The main goal of the project was to create simulations that mirror the real-world challenges faced by cybersecurity experts in a major financial organization. This initiative concentrated on exploring possible cyber threats, spotting signs of security breaches, and outlining detailed steps for resolution. The activities were structured to enhance skills in investigation, analysis, and documentation, which are essential for handling cybersecurity incidents. The program includes two key components: a social engineering probe and a digital forensics examination.

SKILLS LEARNED

- Social Engineering Awareness: Identifying red flags in email content, sender information, and attachment/link behavior. Applying knowledge of common social engineering tactics like phishing.
- Email Analysis: Scrutinizing email headers, sender legitimacy, and attachment types. Understanding how to analyze email content for suspicious elements.
- Digital Forensics: Examining network traffic captured in a pcap file. Identifying user activity based on network data packets. Documenting investigation steps and findings.
- Incident Response & Reporting: Enhanced capability to write clear, technical reports that translate complex security incidents into actionable recommendations for mitigation.
- Network Security: Identifying malicious activity through network traffic analysis and forensic investigation.

TOOLS USED

Wireshark: Used for detailed packet capture (pcap) file analysis and network traffic investigation.
Hex Fiend: to see the raw and exact contents of a file.
Email Header Analysis Tools: To investigate sender metadata and detect spoofing or phishing indicators.
Phishing Detection Techniques: Applied manual and automated methods to assess email authenticity and safety.

______________________________________________________________________________________________________________
Steps
TASK 1: SOCIAL ENGINEERING INVESTIGATION
You've been tasked with reviewing a collection of emails to decide if they are harmful or safe. For any email flagged as malicious, you must produce a brief report detailing why you consider it suspicious. This report should cover aspects like dubious content, harmful attachments or links, unusual sender details, or signs of phishing or malware. The aim is to quickly assess the emails and alert about any dangers so they can be addressed swiftly.

-To confirm that the website was a legitimate and secure ANZ page, I checked for an SSL Certificate. I verified the URL in the browser changed from http:// to https://, signaling a secure connection. I also looked for a lock or key icon near the address bar on pages where security was crucial. Clicking this icon gave me access to the details of ANZ's SSL Certificate, ensuring the site was both authentic and secure.

Below are the 7 emails mentioned:

- Email 1:
<img width="539" alt="email 1" src="https://github.com/user-attachments/assets/896fd553-4e04-4637-bb74-61aaebd23df2" />
Analysis:

Safe or Malicious: Safe
It’s clearly not spam as the reply indicates a previous relationship and that the email was expected and welcome. The date and time could indicate that the conversation was anticipated, as there is next to no delay in a reply.
This email is non malicious. It’s a typical conversation between friends and contains no potentially dangerous artefacts.

- Email 2:
<img width="533" alt="email 2" src="https://github.com/user-attachments/assets/ad6b6716-787c-42ba-a1fd-64425a981dcc" />
Analysis:

Safe or Malicious: Malicious
The email claims to be from one drive but the email sender is from a Russian domain which is well known for malicious emails.
The email tries to get the user to download a file, without providing information about the file’s content, or the sender.
The email’s format is unprofessional and contains poor grammar & spelling. Y
You would not expect an email from an official Microsoft service to be formatted and presented like this.

- Email 3:
<img width="532" alt="email 3" src="https://github.com/user-attachments/assets/ccf4b805-4f67-44b0-944d-2ade32067aed" />
Analysis:

Safe or Malicious: Malicious
The email is presented as a question from a friend who cannot access Facebook, and asks the recipient to follow a link to see if Facebook is working for them. But the link provided is actually a phishing link make to look like facebook.com at first glance.
The senders account could be compromised, so a malicious email like this could still come from a trusted friends account.

- Email 4:
<img width="492" alt="email 4" src="https://github.com/user-attachments/assets/60052fa6-4953-4b98-b3aa-9257af6758c6" />
Analysis:

Safe or Malicious: Safe
This email is an example of generic marketing, it could be regarded as Spam (unwanted or unrequested marketing content). It’s been forwarded twice, but the original sender is a mass mail service.
If googled, the site can be seen as a sales site that contains no malicious content.
The email contains no links or requests for information, just pure advertising.

- Email 5:
<img width="503" alt="email 5" src="https://github.com/user-attachments/assets/189d2a18-fd35-4db8-8b06-1f4d9da44e8f" />
Analysis:

Safe or Malicious: Malicious
The email is requesting the recipient’s credentials for unusual reasons. They’ve tried to make the issue seem urgent, which is a well-known persuasive technique often used for phishing.
The email lacks professionalism which gives more reason to believe it’s a fake.
Legitimate users/services would not ask for account details. This is almost always a sign of malicious activity.

- Email 6:
<img width="517" alt="email 6" src="https://github.com/user-attachments/assets/315b9a23-9e18-47e0-9941-12aafdece9b9" />
Analysis:

Safe or Malicious: Safe
This email is non malicious. It is a typical workplace email. There are no files, links or suspicious requests within the emails, and for the most part internal work emails can be trusted to be safe.
The senders email address matches the name on the signature, and appears to be well formatted and professional.

- Email 7:
<img width="509" alt="email 7" src="https://github.com/user-attachments/assets/1565121d-ca7f-4379-990c-76b72837d536" />
Analysis:

Safe or Malicious: Malicious
The email claims to be from Geico Insurance but the sender doesn’t have an official Geico email address, and the URL provided is not linked to Geico in any way.
The email sender claims to be someone called "Mike Ferris", but the display name of the sender is Val.kill.ma.
Legitimate companies would use HTTPS for any financial transactions. The link provided is just http, which is another indicator that this is a fake. HTTPS is secured and encrypted where as HTTP is not.

_________________________________________________________________________________________
TASK 2: DIGITAL INVESTIGATION OF NETWROK TRAFFIC 
ANZ noticed unusual network behavior from someone using the their network. A laptop has been highlighted by our security measures due to odd internet traffic patterns, and our job is to look into this traffic to see what the user has been accessing and downloading. You'll need to analyze the given packet capture (pcap) file which records the user's recent online activities. The task includes spotting any images viewed, files accessed, and other traces in the data. We are then expected to compile a fully comphrensive report detailing our  discoveries and outline the methods and steps taken during your investigation.

2.1) First of all, I opened the pcap file in wireshark. Then, I filtered the traffic for 'http' only. This view let me see some interesting http GET requests, which indicated that the user specifically requested information.
![Wireshark pcap capture](https://github.com/user-attachments/assets/c8c23111-8fdf-4678-a153-2f340b6ffcee)

2.2) Now, we begin the investigation with anz-logo.jpg.
![image](https://github.com/user-attachments/assets/b8cb2402-fd89-4dcc-9273-220edc11c032)

2.3) To investigate this image download further, I viewed its TCP stream to see what I could find.

![image](https://github.com/user-attachments/assets/8e297008-ebb0-48cd-872a-5720481eabd8)

2.4) Looking through the data in the TCP stream showed that the data contained two headers and a footers for a .jpg image. The header/footer is FFD8 – FFD9 in hex and the images are also recognizeable in ASCII by the string ‘JFIF’ near the start.

![image](https://github.com/user-attachments/assets/162da7bb-536d-48b3-a86e-73d1dc64d258)

2.5) The next step taken was carving out the images from the tcp stream, which I did by taking all the hex from FFD8 to FFD9 and copying it into the hex editor program Hex Fiend.

![image](https://github.com/user-attachments/assets/885515fe-0b9e-4004-86f1-f72146a30719)

2.6) I then saved the file as a jpg and opened it, resulting in the image below.
![anz-logo](https://github.com/user-attachments/assets/2fd2254c-9e8f-4dfc-9d0b-47dd9264cbc3)

2.7) Then I followed the above same procedures for bank-card.jpg resulting in the image of bank-card.

![bank-card](https://github.com/user-attachments/assets/5c30c42f-f47a-439b-91b4-976902f38a55)

2.8) Next, I did same with ANZ1.jpg and ANZ2.jpg 
ANZ1
![ANZ1](https://github.com/user-attachments/assets/511fea82-1ddb-40c6-a78a-294d70085c9c)
ANZ2
![ANZ2](https://github.com/user-attachments/assets/9985c8fa-e95d-4c12-8991-796f9b0a82ee)

2.9) But when I followed the TCP stream and view the data as ASCII for ANZ1 and ANZ2, there were hidden messages as well inside data at the end of image. It said “You've found the hidden message! Images are sometimes more than they appear.”
![image](https://github.com/user-attachments/assets/a8e6654d-fc96-4078-bf03-7cc18064633f)

3.0) Next, I followed "how-to-commit-crimes.docx".
The Ascii view showed the following message:

“Step 1: Find target

Step 2: Hack them

This is a suspicious document.
![image](https://github.com/user-attachments/assets/f7dfdc0c-d383-40bf-961b-5b2ecf2a6952)


3.1) Next, I investigated the 3 pdf documents: ANZ_Document.pdf, ANZ_Document2.pdf, evil.pdf
It was a pdf document so, the hex signature was found to be “25 50 44 46”. So ,I copied all the data to the end beginning with this and got the following results:

3.1.1) ANZ_Document.pdf
![ANZ_Document-pdf](https://github.com/user-attachments/assets/8066cefc-4996-40ac-bd95-69372edaa36e)

3.1.2) ANZ_Document2.pdf
![ANZ_Document2-pdf](https://github.com/user-attachments/assets/9af8703c-3848-451b-8322-da5b90a92904)

3.1.3) evil.pdf
![image](https://github.com/user-attachments/assets/1baa8577-67f6-4651-b937-8c0bb7e548a8)

3.2) Afterwards, I investigated "hiddenmessage2.txt". It had encoded data - as the JPG image is compressed and in JFIF format - and when viewed with hex and had same hex signature as jpg image.
![image](https://github.com/user-attachments/assets/599bd282-a36a-41f4-9a1e-4ec47df22eb3)

3.3) Then,I investigated "atm-image.jpg and extracted the following image:
![atm-image](https://github.com/user-attachments/assets/28b0b0e4-a3ba-4073-8cae-e27ca4d89b69)

3.4) Next, I investigated "broken.png". It did not respond on png hex signature. Then I discovered that the data was encoded in base64. I decrypted the base64 with online tool. After decryption, we got png image data . The image data was further copied in hex and found following image.
![broken](https://github.com/user-attachments/assets/c808a1fe-d493-47dd-83f1-1d605f2389e2)

3.5) In the final sub-task, I investigated the file named "securepdf.pdf". It was not a PDF. It had a message stating: [Password is “secure”] at the bottom. 
![image](https://github.com/user-attachments/assets/4cd6f7fa-c7af-4944-8672-9b19b36b0180)

After analysing the TCP stream I 've also encountered that the coding that was accepted was “gzip" and while examining the pdf as ASCII data it came out that the zip file might contain a file called “rawpdf.pdf”.
I the went on with converting the file into .zip format and tried to access it utilizing the password "secure".
Prompting the password in the window allowed me to access the file and it showed as such:
![image](https://github.com/user-attachments/assets/1a0b16c5-f2a9-43b8-b2e7-eba6e214d26f)

_______________________________________________________________________________________________
CONCLUSION
This project enhanced my expertise in cybersecurity incident management, focusing on tackling social engineering and detecting unusual network behavior. It sharpened my skills in methodically investigating and logging security threats, furtherly improving my reporting and communication skills. 



