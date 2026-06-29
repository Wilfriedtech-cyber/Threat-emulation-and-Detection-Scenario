
<img width="1216" height="1036" alt="image" src="https://github.com/user-attachments/assets/3ac805b0-04b9-481f-8677-5a9bc88b0312" />

BNow back to our kali machine we are going to create an ability (basically an ability is the attack that will be performed on our agents)
<img width="1897" height="905" alt="image" src="https://github.com/user-attachments/assets/bc5eb392-5284-4cdc-a2b0-595de0aa6c88" />


since we want to create a full atack chain, we will be creating a couple of abilities
Ability 1 - lateral movement 
<img width="1161" height="745" alt="image" src="https://github.com/user-attachments/assets/f8457192-cc02-4dfc-862f-5694c6549548" />
<img width="1104" height="722" alt="image" src="https://github.com/user-attachments/assets/c7963c5f-a729-4765-8fd4-94bde5bed9e4" />



ability 2 - data staging
<img width="1122" height="737" alt="image" src="https://github.com/user-attachments/assets/96a5b329-2c1d-4b7b-8b20-00deb8dfc06f" />
<img width="1111" height="732" alt="image" src="https://github.com/user-attachments/assets/7e5d5757-073e-4cd5-ba39-c01448cb855a" />



ability 3 - exfiltration
<img width="1127" height="776" alt="image" src="https://github.com/user-attachments/assets/e1f2c0d8-dbab-4ef4-941e-e6055fd0261c" />
<img width="1135" height="774" alt="image" src="https://github.com/user-attachments/assets/ee542838-f11a-439c-9ca7-84234349fa76" />


Now I have my abilities created 
<img width="1675" height="745" alt="image" src="https://github.com/user-attachments/assets/597a3222-996d-458b-a590-ad00fa5225df" />

I will next create a new adversary profile with the order of those abilities
Lateral Movement → Stage Decoy → Exfil. Order matters 
<img width="1898" height="899" alt="image" src="https://github.com/user-attachments/assets/69187d5f-0d1d-448b-974e-c7bda9ca1421" />


Next step i will run the operation but before i need to make sure that my agents aRE ALIVE ON MY SYSTEMS
<img width="1898" height="900" alt="image" src="https://github.com/user-attachments/assets/0f28227c-9a3c-46aa-b320-cf84c7c4d132" />
<img width="1902" height="890" alt="image" src="https://github.com/user-attachments/assets/97858101-f1bd-45e0-8c7f-7809c9412e51" />

Now that we have ran those attacks we are waiting for it to be finished to start our threat hunting
<img width="1630" height="739" alt="image" src="https://github.com/user-attachments/assets/3edcd10a-9cad-4fe6-a0f2-61b2b78ac4a6" />
As you can see below most of those attacks where succesfull but the data exfiltration attacks didn't succeed because of caldera not accepting the format it is sendfing the data to
But our goal is to analyze the traffic and create dectection
 <img width="1647" height="493" alt="image" src="https://github.com/user-attachments/assets/7631576d-c9f4-4f89-87dc-3342de2c150e" />

Now to splunk: 
we wanna look at the specific share for data exfiltraation and we see that eventID 5140 is triggered whenever someone access a network share 
looking for the eventID 5140 and tailoring it.
<img width="1456" height="920" alt="image" src="https://github.com/user-attachments/assets/a5f82f61-4b7f-4b66-b59f-3b45325ee287" />

We can tailor it to detect our smb share access and save it as a report because we are not able to create an alert for a free splunk
<img width="1405" height="900" alt="image" src="https://github.com/user-attachments/assets/ceb7a792-c207-4989-91ec-e261b7ac741b" />

<img width="1386" height="893" alt="image" src="https://github.com/user-attachments/assets/6985abe0-cd40-44b3-8d73-541867633bac" />


now let's create a detection for the data staging, as you can see the attacked dropped sensitive.txt but what if the attacker drops another file ? so we need a good detection that will take this into consideration
using the Access_Mask=0x2  we can filter this because it is only used when a file is being written on a share C OR admin
<img width="1389" height="887" alt="image" src="https://github.com/user-attachments/assets/3b60d298-db78-41bd-be83-dfe5a50814dc" />


nOW LET'S FIND A DETECTION FOR THE LAST ONE , we wll use 4688 filecreation from powershell and invoke-webrequest commandline and it gives us that
<img width="1389" height="876" alt="image" src="https://github.com/user-attachments/assets/05c70df0-d324-4d04-8446-ad6c941516f3" />

Now we just need to save them as an alert and re run the ability again
<img width="1298" height="843" alt="image" src="https://github.com/user-attachments/assets/0f412d19-61a6-4660-b530-ab48665f30b9" />

Great labs so far 














A couple of notes so you can explain it:

The lateral ability runs net use to .252's ADMIN$ → generates 5140 on the client.
Staging writes across the admin share to the client → generates 5145 on the client, and the PowerShell process itself → 4688.
For exfil, that Invoke-WebRequest generates the outbound traffic Suricata flags. If you'd rather use Caldera's native exfil (cleaner upload), grab the stockpile ability "Find and stage sensitive files" / "Exfil staged directory" instead — Suricata flags the outbound either way, even if the POST errors.
