import requests
import re
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

global prit
prit=201
data = pd.read_csv("host_map.csv")
names = data.name.tolist()
ips = data.ip.tolist()
macs = data.mac.tolist()
rows, cols = (12, 12) 
barr = [[0 for i in range(cols)] for j in range(rows)]
earr = [[0 for i in range(cols)] for j in range(rows)]
barrh1 = np.zeros(10, dtype = int)
earrh1 = np.zeros(10, dtype = int)
#print("Matrix b : \n", b)
bsw1 = np.zeros(10, dtype = int)
esw1 = np.zeros(10, dtype = int)
# Importing the dataset
dataset = pd.read_csv('cd_dst_f1.csv',header=None)
X = dataset.iloc[:, :-1].values
y = dataset.iloc[:, -1].values
# Splitting the dataset into the Training set and Test set
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
# Feature Scaling
from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.transform(X_test)
# Training the Decision tree Classification model on the Training set
#from sklearn.ensemble import RandomForestClassifier
#classifier = RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = 0)
from sklearn.tree import DecisionTreeClassifier
classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
classifier.fit(X_train, y_train)

def getIP(name):
    try:
        index = names.index(name)
        return ips[index]
    except:
        return -1

def getMAC(name):
    try:
        index = names.index(name)
        return macs[index]
    except:
        return -1

def prow(text):
 from nltk.tokenize import word_tokenize
 tokens = word_tokenize(text)
 # convert to lower case
 tokens = [w.lower() for w in tokens]
 # remove punctuation from each word
 import string
 table = str.maketrans('', '', string.punctuation)
 stripped = [w.translate(table) for w in tokens]
 # remove remaining tokens that are not alphabetic
 words = [word for word in stripped if word.isalpha() or word.isnumeric() or word.isalnum()]
 #print(words)
 # filter out stop words
 from nltk.corpus import stopwords
 stop_words = set(stopwords.words('english'))
 stop_words.remove('what')
 stop_words.remove('how')
 words = [w for w in words if not w in stop_words]
 from nltk.stem.wordnet import WordNetLemmatizer
 lemmatizer = WordNetLemmatizer()
 lemma_list_of_words = []
 l2 = ' '.join([lemmatizer.lemmatize(i) for i in words])
 lemma_list_of_words.append(l2)
 return lemma_list_of_words
 #return words
 #print(words[:100])

def check(sentence, words1): 
    res = [all([k in s for k in words1]) for s in sentence] 
    return [sentence[i] for i in range(0, len(res)) if res[i]] 
   
def gnsw():
    print("\nGetting you the list of all the switch IDs which are connected to the controller")
    response = requests.get("http://localhost:8080/stats/switches")
    print("RESPONSE CODE         : ",str(response.status_code))
    x=str(response.content.decode())
    print("Switch IDs present are: ",x)
    c=x.count(",") 
    print("Number of switches are: ",(c+1))
    print()
    return

def gdsw(num):
  if(1<=int(num) and int(num)<=int(MSW)):
    print("\nGetting you the description of switch with ID:"+str(num))
    response = requests.get("http://localhost:8080/stats/desc/"+str(num))
    print("[RESPONSE CODE] " + str(response.status_code))
    if(str(response.status_code)!='200'):
      print("There is an error")
      print()
      return
    else:  
      x=str(response.content.decode())
      y=json.loads(x)
      print("\nManufacturer description ::"+ str(y[num]['mfr_desc']))
      print("Hardware description       ::"+ str(y[num]['hw_desc']))
      print("Software description       ::"+ str(y[num]['sw_desc']))
      print("Serial number              ::"+ str(y[num]['serial_num']))
      print("Datapath description       ::"+ str(y[num]['dp_desc'])+"\n")
      return
  else:
    print("ERROR")
    print()
    return
    
def gfsw(num):
  if(1<=int(num) and int(num)<=int(MSW)):
    print("\nGetting you the flow entry of switch with ID:"+str(num))
    response = requests.get("http://localhost:8080/stats/flow/"+str(num))
    print("[RESPONSE CODE] " + str(response.status_code))
    if(str(response.status_code)!='200'):
      print("There is an error")
      print()
      return
    else:  
      x=str(response.content.decode())
      y=json.loads(x)
      #print("Flow entry of switch is: " + x) 
      y1=y[num]
      for y2 in y1:
        print("\nPriority        :"+ str(y2['priority']))
        print("Cookie          :"+ str(y2['cookie']))
        print("Idle Timeout    :"+ str(y2['idle_timeout']))
        print("Hard Timeout    :"+ str(y2['hard_timeout']))
        print("Actions         :"+ str(y2['actions']))
        print("Match           :"+ str(y2['match']))
        print("Byte Count      :"+ str(y2['byte_count']))
        print("Duration Sec.   :"+ str(y2['duration_sec']))
        print("Duration nSec.  :"+ str(y2['duration_nsec']))
        print("Packet Count    :"+ str(y2['packet_count']))
        print("Table ID        :"+ str(y2['table_id']))
      #print(y1[0]['priority'])
      #print(y['cookie'])      
      print()
      return
  else:
    print("ERROR")
    print()
    return
  
def gfswrid(num):
    #print(num)
    if(len(num)==1):
      swid="000000000000000"+str(num[0])
      #print(swid)
      response= requests.get("http://localhost:8080/firewall/rules/"+str(swid))
      print("\n[RESPONSE CODE] " + str(response.status_code))
      if(str(response.status_code)!='200'):
       print("There is an error")
       print()
       return
      else: 
       x=str(response.content.decode())
       y=json.loads(x)
       #print("Flow entry of switch is: " + x) 
       y1=y[0]
       #y2=y1['rules']
       y2=y1['access_control_list']
       y3=y2[0]
       y4=y3['rules']
       for y5 in y4:
         print()
         print(y5)
       print()
       return
    else:
      print("ERROR")
      print()
      return
          
def bkt(res):
    global prit
    res.sort()
    if(len(res)==1):
      a=str(res[0])
      nm="host"+a
      nw_src=str(getIP(nm))
      prit=prit+1
      prits=str(prit)
      data={"priority":prits,"nw_proto":"ICMP","nw_src":nw_src,"actions":"DENY"}
      response=requests.post('http://localhost:8080/firewall/rules/all',json=data)
      print("\n[RESPONSE CODE] " + str(response.status_code))
      if(str(response.status_code)!='200'):
        print("There is an error")
        print()
      return
    elif(len(res)==2):
      a=str(res[0])
      b=str(res[1])
      nm1="host"+a
      nm2="host"+b
      nw_src=str(getIP(nm1))
      nw_dst=str(getIP(nm2))
      prit=prit+1
      prits=str(prit)
      data={"priority":prits,"nw_proto":"ICMP","nw_src":nw_src,"nw_dst":nw_dst,"actions":"DENY"}
      response=requests.post('http://localhost:8080/firewall/rules/all',json=data)
      print("\n[RESPONSE CODE] " + str(response.status_code))
      if(str(response.status_code)!='200'):
        print("There is an error")
      print()
      return
    else:
      print("\nThere is an error, please enter either one host or two hosts to be blocked")
      print()
      return
     
def cdbkt(res):
   if(len(res)==2):
    n1=int(res[0])
    n2=int(res[1])
    List=[]
    if(len(res)==2):
      barr[n1][n2]=1
      barr[n2][n1]=1
      c=1
      for i in range(1,12):
       if(c!=n1):
        List.insert(len(List),barr[n1][i])
       c=c+1
      c=1
      for i in range(1,12):
       if(c!=n1):
        List.insert(len(List),earr[n1][i])
       c=c+1
      """c=0
      for i in barr[n1]:
       if(c!=n1):
        List.insert(len(List),i)
       c=c+1
      c=0
      for i in earr[n1]:
       if(c!=n1):
        List.insert(len(List),i)
       c=c+1"""
      cd1=classifier.predict(sc.transform([List]))
      c=1
      List=[]
      for i in range(1,12):
       if(c!=n2):
        List.insert(len(List),barr[n2][i])
       c=c+1
      c=1
      for i in range(1,12):
       if(c!=n2):
        List.insert(len(List),earr[n2][i])
       c=c+1
      cd2=classifier.predict(sc.transform([List]))
      #print("cd"+str(cd))
      if(cd1==1 and cd2==1):
        print("\nContradiction detected,Do you want to proceed? Yes/No:\n")
        ch=str(input())
        ch=ch.lower()
        while(ch!="yes" and ch!="no"):
         ch=input("Enter Yes or No:\n")
         ch=ch.lower()
        if(ch=="yes"):
          earr[n1][n2]=0
          earr[n2][n1]=0
          bkt(res)
          return
        elif(ch=="no"):
          barr[n1][n2]=0
          barr[n2][n1]=0
          earr[n1][n2]=1
          earr[n2][n1]=1
          return 
      else:
        earr[n1][n2]=0
        earr[n2][n1]=0
        bkt(res)
        return       
   elif(len(res)==1):
    n1=int(res[0])
    List=[]
    cd=0
    barrh1[n1-1]=1
    for i in barrh1:
     List.insert(len(List),i)
    for i in earrh1:
     List.insert(len(List),i)
    cd=classifier.predict(sc.transform([List]))
    if(cd==0):
     earrh1[n1-1]=0 
     bkt(res)
     return
    elif(cd==1):
     print("\nContradiction detected,Do you want to proceed? Yes/No:\n ")
     ch=str(input())
     ch=ch.lower()
     while(ch!="yes" and ch!="no"):
      ch=input("Enter Yes or No:\n ")
      ch=ch.lower()
     if(ch=="yes"):
      earrh1[n1-1]=0
      bkt(res)
      return
     elif(ch=="no"):
      barrh1[n1-1]=0
      earrh1[n1-1]=1
      return  
    else:
     return    
           
def ent(res):
     global prit
     res.sort()
     if(len(res)==1):
      a=str(res[0])
      nw_src="10.0.0."+a
      prit=prit+1
      prits=str(prit)
      data={"priority":prits,"nw_proto":"ICMP","nw_src":nw_src}
      response=requests.post('http://localhost:8080/firewall/rules/all',json=data)
      data1={"priority":prits,"nw_proto":"ICMP","nw_dst":nw_src}
      response1=requests.post('http://localhost:8080/firewall/rules/all',json=data1)
      print("\n[RESPONSE CODE] " + str(response.status_code))
      if(str(response.status_code)!='200'):
        print("There is an error")
      print()
      return
     elif(len(res)==2):
      a=str(res[0])
      b=str(res[1])
      nw_src="10.0.0."+a
      nw_dst="10.0.0."+b
      prit=prit+1
      prits=str(prit)
      data={"priority":prits,"nw_proto":"ICMP","nw_src":nw_src,"nw_dst":nw_dst}
      response=requests.post('http://localhost:8080/firewall/rules/all',json=data)
      data1={"priority":prits,"nw_proto":"ICMP","nw_src":nw_dst,"nw_dst":nw_src}
      response1=requests.post('http://localhost:8080/firewall/rules/all',json=data1)
      print("[RESPONSE CODE] " + str(response.status_code))
      if(str(response.status_code)!='200'):
        print("There is an error")
        print()
      return
     else:
      print("There is an error, please enter either one host or two hosts to be blocked")
      print()
      return

def cdent(res):
   if(len(res)==2):
    n1=int(res[0])
    n2=int(res[1])
    List=[]
    if(len(res)==2):
      earr[n1][n2]=1
      earr[n2][n1]=1
      c=1
      for i in range(1,12):
       if(c!=n1):
        List.insert(len(List),barr[n1][i])
       c=c+1
      c=1
      for i in range(1,12):
       if(c!=n1):
        List.insert(len(List),earr[n1][i])
       c=c+1
      """c=0
      for i in barr[n1]:
       if(c!=n1):
        List.insert(len(List),i)
       c=c+1
      c=0
      for i in earr[n1]:
       if(c!=n1):
        List.insert(len(List),i)
       c=c+1"""
      cd1=classifier.predict(sc.transform([List]))
      c=1
      List=[]
      for i in range(1,12):
       if(c!=n2):
        List.insert(len(List),barr[n2][i])
       c=c+1
      c=1
      for i in range(1,12):
       if(c!=n2):
        List.insert(len(List),earr[n2][i])
       c=c+1
      cd2=classifier.predict(sc.transform([List]))
      #print("cd"+str(cd))
      if(cd1==1 and cd2==1):
        print("\nContradiction detected,Do you want to proceed? Yes/No:\n ")
        ch=str(input())
        ch=ch.lower()
        while(ch!="yes" and ch!="no"):
         ch=input("Enter Yes or No:\n ")
         ch=ch.lower()
        if(ch=="yes"):
          barr[n1][n2]=0
          barr[n2][n1]=0
          ent(res)
          return
        elif(ch=="no"):
          earr[n1][n2]=0
          earr[n2][n1]=0
          barr[n1][n2]=1
          barr[n2][n1]=1
          return
      else:
        barr[n1][n2]=0
        barr[n2][n1]=0
        ent(res)
        return       
   elif(len(res)==1):
    n1=int(res[0])
    List=[]
    cd=0
    earrh1[n1-1]=1
    for i in barrh1:
     List.insert(len(List),i)
    for i in earrh1:
     List.insert(len(List),i)
    cd=classifier.predict(sc.transform([List]))
    if(cd==0):
     barrh1[n1-1]=0 
     ent(res)
     return
    else:
     print("\nContradiction detected,Do you want to proceed? Yes/No:\n ")
     ch=str(input())
     ch=ch.lower()
     while(ch!="yes" and ch!="no"):
      ch=input("Enter Yes or No:\n ")
      ch=ch.lower()
     if(ch=="yes"):
      barrh1[n1-1]=0
      ent(res)
      return
     elif(ch=="no"):
      barrh1[n1-1]=1
      earrh1[n1-1]=0
      return  
   else:
     print("ERROR or Intent cannot be processed")
     print()
     return
    
def gsts():
    response=requests.get("http://localhost:8080/firewall/module/status")
    x=str(response.content.decode())
    y=json.loads(x)
    print()
    for y1 in y:
       s1=str(y1['switch_id'])
       print("\n Switch ID    :"+ str(int(str(s1), 16)))
       print("Status          :"+ str(y1['status']))
    print()
    return
    
def enswid(res):
 #for i in res:
 if(len(res)==1):
  n1=format(int(res[0]),'x')
  sid="000000000000000"+str(n1)
  response = requests.put("http://localhost:8080/firewall/module/enable/"+str(sid))        
  x=str(response.content.decode())
  print("\nRESPONSE CODE "+str(response.status_code))
 else:
  print("\nError please enter only one switch id")
 print()
 return

def cdenswid(res):
 if(len(res)==1):
    n1=int(res[0])
    List=[]
    cd=0
    esw1[n1-1]=1
    for i in bsw1:
     List.insert(len(List),i)
    for i in esw1:
     List.insert(len(List),i)
    cd=classifier.predict(sc.transform([List]))
    if(cd==0):
     bsw1[n1-1]=0 
     enswid(res)
     return
    else:
     print("\nContradiction detected,Do you want to proceed? Yes/No:\n")
     ch=str(input())
     ch=ch.lower()
     while(ch!="yes" and ch!="no"):
      ch=input("Enter Yes or No:\n ")
      ch=ch.lower()
     if(ch=="yes"):
      bsw1[n1-1]=0
      enswid(res)
      return
     elif(ch=="no"):
      bsw1[n1-1]=1
      esw1[n1-1]=0
      return 
 else:
     print("Error or not able to handle")
     print()
     return   
    
def diswid(res):
 #print(res)
 #for i in res:
 if(len(res)==1):
  n1=format(int(res[0]),'x')
  sid="000000000000000"+str(n1)
  response = requests.put("http://localhost:8080/firewall/module/disable/"+str(sid))        
  x=str(response.content.decode())
  print("\nRESPONSE CODE "+str(response.status_code))
 else:
  print("Error please enter only one switch id")
 return
  
def cddiswid(res):
 if(len(res)==1):
    n1=int(res[0])
    List=[]
    cd=0
    bsw1[n1-1]=1
    for i in bsw1:
     List.insert(len(List),i)
    for i in esw1:
     List.insert(len(List),i)
    cd=classifier.predict(sc.transform([List]))
    if(cd==0):
     esw1[n1-1]=0 
     diswid(res)
     return
    else:
     print("Contradiction detected,Do you want to proceed? Yes/No:\n ")
     ch=str(input())
     ch=ch.lower()
     while(ch!="yes" and ch!="no"):
      ch=input("Enter Yes or No:\n ")
      ch=ch.lower()
     if(ch=="yes"):
      esw1[n1-1]=0
      diswid(res)
      return
     elif(ch=="no"):
      bsw1[n1-1]=0
      esw1[n1-1]=1
      return  
 else:
     print("ERROR or Intent cannot be processed")
     return    
    
def dlrsw():
 print("\nNOTE: Please do not delete any flow entries which are currently in use by RYU controller")
 rid=int(input("RULE ID: "))
 swid=str(input("SWITCH ID: "))
 if(1<=int(swid)<=MSW):
  n1=format(int(swid),'x')
  sid="000000000000000"+str(n1)
  data={"rule_id": str(rid)}
  response = requests.delete("http://localhost:8080/firewall/rules/"+str(sid),json=data)
  print("RESPONSE CODE "+str(response.status_code))
 else:
  print("ERROR found")
 return

def gpsts(res):
 response = requests.get("http://localhost:8080/stats/port/"+str(res[0]))
 x=response.content.decode()
 y=json.loads(x)
 num=res[0]
 y1=y[num]
 c=0
 for y2 in y1:
  if(c!=0):
   print()
   print("Port number:                       ",y2['port_no'])
   print("Received Packets:                  ",y2['rx_packets'])
   print("Transmitted Packets:               ",y2['tx_packets'])
   print("Received Bytes:                    ",y2['rx_bytes'])
   print("Transmitted Bytes:                 ",y2['tx_bytes'])
   print("Packets dropped(receiver side):    ",y2['rx_dropped'])
   print("Packets dropped(transmitter side): ",y2['tx_dropped'])
   print("Received packets errors:           ",y2['rx_errors'])
   print("Transmitted packets errors:        ",y2['tx_errors'])   
   print("Collisions:                        ",y2['collisions'])   
   print("Duration(sec):                     ",y2['duration_sec'])   
  c=c+1
 return

def afsts(res):
 response = requests.get("http://localhost:8080/stats/aggregateflow/"+str(res[0]))
 x=response.content.decode()
 y=json.loads(x)
 num=res[0]
 y1=y[num]
 for y2 in y1:
   print()
   print("Packet Count : ",y2['packet_count'])
   print("Byte Count   : ",y2['byte_count'])
   print("Flow Count   : ",y2['flow_count'])
 return
    
# Driver code 
response1 = requests.put("http://localhost:8080/firewall/module/enable/all")
#print("[RESPONSE CODE] " + str(response1.status_code))
#print("[RESPONSE] " + response1.content.decode())
prits=str(prit)
data1={"priority":prits,"nw_proto":"ICMP"}
response2 =requests.post('http://localhost:8080/firewall/rules/all',json=data1) 
response = requests.get("http://localhost:8080/stats/switches")
x=str(response.content.decode())
MSW=int(x.count(",")) 
MSW=MSW +1
print("Hello! Please enter your intent")
text=str(input())
#text=text.lower()

kw1_1= ['get','number', 'switch']
kw1_2=['what','number','switch']
kw1_3=['how','many','switch']
  
kw2_1=['get','description','switch']
kw2_2=['get','detail','switch'] 
kw2_3=['show','description','switch']
kw2_4=['show','detail','switch'] 
kw2_5=['display','description','switch']
kw2_6=['display','detail','switch']
kw2_7=['what','detail','switch'] 
    
kw3_1=['get','detailed','flow','entry','switch']
kw3_2=['get','detailed','flow','switch']
kw3_3=['show','detailed','flow','entry','switch']
kw3_4=['show','detailed','flow','switch']
kw3_5=['display','detailed','flow','entry','switch']
kw3_6=['display','detailed','flow','switch']
  
kw5_1=['block','host']
kw5_2=['deny','host']
kw5_3=['disable','host']
kw5_4=['deactivate','host']  
  
kw6_1=['allow','host']
kw6_2=['enable','host']
kw6_3=['activate','host']
kw6_4=['forward','host']
  
kw7_1=['get','ip']
kw7_2=['get','mac']
kw7_3=['get','i.p.']
kw7_4=['get','m.a.c']
   
kw8_1=['overall','status','switch']
  
kw9_1=['block','switch']
kw9_2=['deny','switch']
kw9_3=['disable','switch']
kw9_4=['deactivate','switch']
  
kw10_1=['enable','switch']
kw10_2=['allow','switch']
kw10_3=['activate','switch']
    
kw11_1=['delete']
kw11_2=['remove']
  
kw12_1=['get','flow','entry','switch','rule']
kw12_2=['get','flow','switch','rule']
kw12_3=['show','flow','entry','switch','rule']
kw12_4=['show','flow','switch','rule']
kw12_5=['display','flow','entry','switch','rule']
kw12_6=['display','flow','switch','rule']

kw13_1=['get','port','status','switch']
kw13_2=['what','port','status','switch']
kw13_3=['show','port','status','switch']
kw13_4=['display','port','status','switch']

kw14_1=['get','aggregate','flow','switch']
kw14_2=['what','aggregate','flow','switch']
kw14_3=['show','aggregate','flow','switch']
kw14_4=['display','aggregate','flow','switch']

  
while(text!='exit'):
  #text=text.lower()
  #w1=prow(text)
  sentence=prow(text)
  #print("sentence ",sentence)
  #sentence = [' '.join(w1)]
  #print(sentence)
  if( check(sentence, kw1_1) or check(sentence, kw1_2) or check(sentence, kw1_3) ):
    print()
    gnsw()
    print()
    print("Please enter new intent or enter exit")
    text=str(input()) 
  
  elif(check(sentence,kw3_1) or check(sentence,kw3_2) or check(sentence,kw3_3) or check(sentence,kw3_4) or check(sentence,kw3_5) or    check(sentence,kw3_6) ):   
    #print(s1)
    s1=str(sentence)
    #print(s1)
    res = ''.join(filter(lambda i: i.isdigit(), s1))
    num=str(res)
    print()
    gfsw(num)
    print()
    print("Please enter new intent or enter exit")
    text=str(input()) 
    
  elif(check(sentence,kw2_1) or check(sentence,kw2_2) or check(sentence,kw2_3) or check(sentence,kw2_4) or check(sentence,kw2_5) or    check(sentence,kw2_6) or check(sentence,kw2_7) ):   
    #temp = re.findall(r'\d+', s1) 
    #res = list(map(int, temp))
    res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    num=res
    #print(num)
    print()
    gdsw(num)
    print()
    print("Please enter new intent or enter exit")
    text=str(input()) 
    
  elif(check(sentence,kw5_1) or check(sentence,kw5_2) or check(sentence,kw5_3) or check(sentence,kw5_4)):
    print()
    temp = re.findall(r'\d+', str(sentence)) 
    res = list(map(int, temp))
    #res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    #print(res)
    mx=int(max(res))
    if(1<=mx<=10):
     cdbkt(res)
    elif(mx>10):
     bkt(res)
    else:
     print("ERROR")
    print()
    print("Please enter new intent or enter exit")
    text=str(input()) 
    
  elif(check(sentence,kw6_1) or check(sentence,kw6_2) or check(sentence,kw6_3) or check(sentence,kw6_4)):
    #res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    print()
    temp = re.findall(r'\d+', str(sentence)) 
    res = list(map(int, temp))
    mx=int(max(res))
    if(1<=mx<=10):
     cdent(res)
    elif(mx>10):
     ent(res)
    else:
     print("ERROR")
    print()
    print("Please enter new intent or enter exit")
    text=str(input()) 
  
  elif(check(sentence,kw7_1) or check(sentence,kw7_3)):
    #res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    print()
    temp = re.findall(r'\d+', str(sentence)) 
    res = list(map(int, temp))
    if(len(res)==1):
     dname="host"+str(res[0])
     ip = getIP(dname)
     print("\nIP address is :"+str(ip))
    else:
     print("ERROR or Intent cannot be processed")
    print()
    print("Please enter new intent or enter exit")
    text=str(input())
    
  elif(check(sentence,kw7_2) or check(sentence,kw7_4)):
    #res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    print()
    temp = re.findall(r'\d+', str(sentence)) 
    res = list(map(int, temp))
    if(len(res)==1):
     dname="host"+str(res[0])
     mac = getMAC(dname)
     print("\nMAC address is :"+str(mac))
    else:
     print("ERROR or Intent cannot be processed")
    print()
    print("Please enter new intent or enter exit")
    text=str(input())
    
  elif(check(sentence,kw8_1)):
    print()
    gsts()
    print()
    print("Please enter new intent or enter exit")
    text=str(input())
      
  elif(check(sentence,kw10_1) or check(sentence,kw10_2) or check(sentence,kw10_3) ):
    #res=[int(num) for num in re.findall(r"\d+", str(sentence))]
    #print(res[0])
    #print(res[1])
    #res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    print()
    temp = re.findall(r'\d+', str(sentence)) 
    res = list(map(int, temp))
    if(1<=int(res[0])<=10):
     cdenswid(res)
    elif(int(res[0]>10)):
     enswid(res)
    else:
     print("ERROR or Intent cannot be processed")
    print()
    print("Please enter new intent or enter exit")
    text=str(input())
  
  elif(check(sentence,kw9_1) or check(sentence,kw9_2) or check(sentence,kw9_3) or check(sentence,kw9_4)):
    #res=[int(num) for num in re.findall(r"\d+", str(sentence))]
    #print(res[0])
    #print(res[1])
    #res = ''.join(filter(lambda i: i.isdigit(), str(sentence)))
    print()
    temp = re.findall(r'\d+', str(sentence)) 
    res = list(map(int, temp))
    if(1<=int(res[0])<=10):
     cddiswid(res)
    elif(int(res[0]>10)):
     diswid(res)
    else:
     print("ERROR or Intent cannot be processed")
    print()
    print("Please enter new intent or enter exit")
    text=str(input())
  
  elif(check(sentence,kw11_1) or check(sentence,kw11_2)):
    print()
    dlrsw()
    print()
    print("Please enter new intent or enter exit")
    text=str(input())
   
  elif(check(sentence,kw12_1) or check(sentence,kw12_2) or check(sentence,kw12_3) or check(sentence,kw12_4) or check(sentence,kw12_5) or    check(sentence,kw12_6) ):
   #s1=str(sentence)
   #res=[int(num) for num in re.findall(r"\d+", str(s1))]
   print()
   temp = re.findall(r'\d+', str(sentence)) 
   res = list(map(int, temp))
   num=str(res[0])
   gfswrid(num)
   print()
   print("Please enter new intent or enter exit")
   text=str(input())   

  elif(check(sentence,kw13_1) or check(sentence,kw13_2) or check(sentence,kw13_3) or check(sentence,kw13_4)):
   print()
   temp = re.findall(r'\d+', str(sentence)) 
   res = list(map(int, temp))
   num=str(res[0])
   gpsts(num)
   print()
   print("Please enter new intent or enter exit")
   text=str(input())
      
  elif(check(sentence,kw14_1) or check(sentence,kw14_2) or check(sentence,kw14_3) or check(sentence,kw14_4)):
   print()
   temp = re.findall(r'\d+', str(sentence)) 
   res = list(map(int, temp))
   num=str(res[0])
   afsts(num)
   print()
   print("Please enter new intent or enter exit")
   text=str(input())
       
  else:
    print()
    print("Sorry, intent cannot be processed. Please enter new intent or enter exit")
    print()
    text=str(input())
    
print("Thank you we will meet again")
