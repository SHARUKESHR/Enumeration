# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:

Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain yahoo.com
#output
![1](https://github.com/user-attachments/assets/325381fc-f4ae-4ffc-8273-ee97a4109b62)


filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com
#output
![2](https://github.com/user-attachments/assets/365f7043-9bad-4207-b108-5d2a9b292965)



intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.

#output
![3](https://github.com/user-attachments/assets/16ec7863-336d-41ac-ae86-eeeeb42ecedb)

inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.

#output
![4](https://github.com/user-attachments/assets/0991cfaf-d2bf-4767-af42-a67ab0683700)

intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.

#output
![5](https://github.com/user-attachments/assets/6c9bd408-125a-468e-9d5c-6afde9d9c736)

link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.

#output
![7](https://github.com/user-attachments/assets/2d955ba9-49ce-44fb-865a-4e47494af1fa)

cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.
#output
![8](https://github.com/user-attachments/assets/8e61f660-80cf-4f28-9716-3ba5b1cee175)

 
#DNS Enumeration


##DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion
## OUTPUT:







##dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:
#output
![WhatsApp Image 2024-09-25 at 08 40 02_5aa950d3](https://github.com/user-attachments/assets/4e29238e-80b3-40f1-99e6-22a5aeeee131)

![WhatsApp Image 2024-09-25 at 08 40 02_523185f1](https://github.com/user-attachments/assets/fe2cd800-e5d6-4a21-b076-66b8b1907a6f)

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.

![WhatsApp Image 2024-09-25 at 08 40 03_c222c76b](https://github.com/user-attachments/assets/2055e968-4266-4593-91c0-59152a4f66bf)


##smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.

![WhatsApp Image 2024-09-25 at 08 40 03_64a3fbe5](https://github.com/user-attachments/assets/e1e02ae6-c8d4-4183-b6f3-73e8e500c728)

In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 ##Output
  
  ![WhatsApp Image 2024-09-25 at 08 40 03_5d90072e](https://github.com/user-attachments/assets/6e4c8b86-fb46-43af-a248-b00230e063ee)


## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.


## OUTPUT:

![WhatsApp Image 2024-09-25 at 08 40 04_c9ce5c32](https://github.com/user-attachments/assets/e09f63dc-da1e-4b92-9c97-f2fcdaab1866)

## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully

