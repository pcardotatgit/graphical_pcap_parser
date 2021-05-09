'''
    version 20210402
'''
import sys
import csv
from crayons import red,green,cyan,yellow
import json
from pathlib import Path
  
# depth  = number of levels you want to dig into. min = 3, max = 5
depth=4
first=0
# CSV column indexes  ( between 1 to 5 )  0 not allowed. The first column of the CSV file must contains the trunk's name
column_level1=1 #floors ( to keep a meaningful information about the mapping between csv column indexes and RGRAPH sublevels
column_level2=2 #switches
column_level3=3 #mac_adresses 
column_level4=4 #ip _addresses
column_level5=5 #OS 

children0_json=''
level1SL=[] 
level2SL=[] 
level3SL=[] 
level4SL=[] 
level5SL=[] 
data_dict={}

'''
for future uses
here = Path(__file__).parent.absolute()
#repository_root = (here / "..").resolve()
repository_root = (here / ".").resolve()
sys.path.insert(0, str(repository_root))

z_var_json = here / f"/output/z_var_json.json"
'''
def new_id(previous_id):
    new_id=previous_id+1
    if new_id< 10:
        new_id_str="000"+str(new_id)
    elif new_id< 100:
        new_id_str="00"+str(new_id)   
    elif new_id< 1000:
        new_id_str="0"+str(new_id)   
    elif new_id< 10000:
        new_id_str=str(new_id)          
    return new_id
    
if __name__ == "__main__":
    fh = open('./static/z_var_json.json', "w")
    #print(cyan('Add head of the resulting data.js file'))
    output_file=open("./static/data.js", "w")
    with open ('./resources/head_of_data_file.txt') as head_file:
        text=head_file.read()
    output_file.write(text)
    #print(green('- Ok Done'))
    ##print(cyan('read ./datas/data.csv file and create json variable'))
    file='./datas/data.csv'
    lines=[]
    level1s=[]
    level2s=[]
    level3=[]
    level4=[]
    level5=[]
    object_id=0
    json_var_text=''
    Main_Dict_Tree=[]
    level0_dict={}
    level2_dict={}
    level3_dict={}  
    level4_dict={}
    level5_dict={}
    index=0      
    with open (file) as csvfile:
        reader = csv.reader(csvfile, delimiter=';')  
        lines = list(reader)
        level0_dict.update({"id":"0"})        
        root_name=lines[1][0]
        #print(' ROOT NAME = ',root_name)
        level0_dict.update({"name":root_name})
        level0_dict.update({"data": {"relation":f"<center><h2>{root_name}</h2></center>"}} )         
        data0_dict={}
        for row in lines:                    
            if row[column_level1] not in level1s:
                level1s.append(row[column_level1])
        level1_dict={}
        for level1 in level1s:
            #print (cyan('- index : '+str(index),bold=True))        
            index+=1      
            level1_dict["id"]=str(new_id(object_id))
            object_id+=1
            if first==0:            
                level1_dict["name"]="## "+level1
                first=1
            else:
                level1_dict["name"]=level1
            data_dict.clear()
            url_link='<a href="javascript:popup_window(\'https://www.google.com\', \'title_title\', 600, 600);">Some actions Here</a>'
            data_dict[object_id]={'relation':f'Some text to customize here for {level1} +*+<br>{url_link}'}
            ##print(red(data_dict[object_id],bold=True))
            level1_dict["data"]=data_dict[object_id]
            ##print (yellow('- ADDING to level1SL : '+json.dumps(level1_dict),bold=True))      
            level2_dict={}     
            level2SL.clear()
            level2s.clear()
            #print (red('- level1 = '+level1,bold=True))
            for row in lines:                
                if row[column_level1]==level1:
                    if row[column_level2] not in level2s:
                        level2_dict.clear()
                        level2s.append(row[column_level2])
                        #print (cyan('- level2 = '+row[column_level2],bold=True))         
                        level2_dict["id"]=str(new_id(object_id))
                        object_id+=1
                        level2_dict["name"]=row[column_level2]
                        data_dict.clear()
                        url_link='<a href="javascript:popup_window(\'https://www.google.com\', \'title_title\', 600, 600);">Some actions Here</a>'
                        data_dict[object_id]={'relation':f'Some text to customize here for <b>{row[column_level2]}</b> +**+<br>{url_link}'}
                        ##print(red(data_dict[object_id],bold=True))
                        level2_dict["data"]=data_dict[object_id]
                        ##print (cyan('- ADDING to level2SL : '+json.dumps(level2_dict),bold=True))  
                        if level2_dict not in level2SL:     
                            dictionary_copy = level2_dict.copy()
                            level2SL.append(dictionary_copy)
                        if depth>=3:
                            level3SL.clear()  
                            level3.clear()
                            for rowB in lines:  
                                if rowB[column_level2]==row[column_level2]:
                                    level3_dict={} 
                                    if rowB[column_level3] not in level3:
                                        level3.append(rowB[column_level3])
                                        #print (yellow('- level3 = '+row[column_level3],bold=True))
                                        ##print (green('--- '+rowB[column_level3]))   
                                        level3_dict["id"]=str(new_id(object_id))
                                        object_id+=1
                                        level3_dict["name"]=rowB[column_level3]   
                                        data_dict.clear()
                                        url_link='<a href="javascript:popup_window(\'https://www.google.com\', \'title_title\', 600, 600);">Some actions Here</a>'
                                        data_dict[object_id]={'relation':f'Some text to customize here for {rowB[column_level3]} +***+<br>{url_link}'}
                                        ##print(red(data_dict[object_id],bold=True))
                                        level3_dict["data"]=data_dict[object_id]                                    
                                        ##print (cyan('- ADDING to level3SL : '+json.dumps(level3_dict),bold=True))  
                                        if level3_dict not in level3SL:     
                                            dictionary_copy = level3_dict.copy()
                                            level3SL.append(dictionary_copy)
                                        if depth>=4:
                                            # Next level begining  IP Addresses
                                            # IP Addresses
                                            level4.clear()
                                            level4_dict.clear()
                                            level4SL.clear()
                                            for rowC in lines:  # lire chaque ligne du fichier une par une
                                                if rowB[column_level3]==rowC[column_level3]: # si la valeur de la cellule dans cette ligne est égale à la valeur de l'objet parent
                                                    if rowC[column_level4] not in level4: 
                                                        level4.append(rowC[column_level4])                                                        
                                                        #print (yellow('- level4 = '+rowC[column_level4],bold=True))
                                                        level4_dict["id"]=str(new_id(object_id))
                                                        object_id+=1     
                                                        level4_dict["name"]=rowC[column_level4] 
                                                        data_dict.clear()
                                                        url_link='<a href="javascript:popup_window(\'https://www.google.com\', \'title_title\', 600, 600);">Some actions Here</a>'
                                                        data_dict[object_id]={'relation':f'Some text to customize here for {rowC[column_level4]} +****+<br>{url_link}'}
                                                        ##print(red(data_dict[object_id],bold=True))
                                                        level4_dict["data"]=data_dict[object_id]                                         
                                                        #print (cyan('- ADDING to level4SL : '+json.dumps(level4_dict),bold=True)) 
                                                        if level4_dict not in level4SL:     
                                                            dictionary_copy = level4_dict.copy()
                                                            level4SL.append(dictionary_copy)
                                                            if depth>=5:
                                                                # Next level begining  OS
                                                                # OS
                                                                level5.clear()
                                                                level5_dict.clear()
                                                                level5SL.clear()
                                                                for rowD in lines:  # lire chaque ligne du fichier une par une
                                                                    if rowC[column_level4]==rowD[column_level4]: # si la valeur de la cellule dans cette ligne est égale à la valeur de l'objet parent
                                                                        if rowD[column_level3] not in level5: 
                                                                            level5.append(rowD[column_level5])
                                                                            #print (yellow('---- '+rowD[column_level5]))   
                                                                            level5_dict["id"]=str(new_id(object_id))
                                                                            object_id+=1     
                                                                            level5_dict["name"]=rowD[column_level5] 
                                                                            data_dict.clear()
                                                                            url_link='<a href="javascript:popup_window(\'https://www.google.com\', \'title_title\', 600, 600);">Some actions Here</a>'
                                                                            data_dict[object_id]={'relation':f'Some text to customize here for {rowD[column_level3]} +****+<br>{url_link}'}
                                                                            ##print(red(data_dict[object_id],bold=True))
                                                                            level5_dict["data"]=data_dict[object_id]
                                                                            #print (cyan('- ADDING to level5SL : '+json.dumps(level5_dict),bold=True)) 
                                                                            if level5_dict not in level5SL:     
                                                                                dictionary_copy = level5_dict.copy()
                                                                                level5SL.append(dictionary_copy)
                                                                            '''
                                                                            NEXT SUB LEVEL
                                                                            '''
                                                            #print (yellow('- level5SL to add to level4_dict children : '+json.dumps(level5SL),bold=True))
                                                            list_copy = level5SL.copy()
                                                            level4_dict.update({"children":list_copy})
                                                            if level4_dict not in level4SL:     
                                                                dictionary_copy = level4_dict.copy()
                                                                level4SL.append(dictionary_copy)   
                                                            # Next level End  OS
                                        #print (yellow('- level4SL to add to level3_dict children : '+json.dumps(level4SL),bold=True))
                                        list_copy = level4SL.copy()
                                        level3_dict.update({"children":list_copy})
                                        if level3_dict not in level3SL:     
                                            dictionary_copy = level3_dict.copy()
                                            level3SL.append(dictionary_copy)   
                                        # Next level End  IP Addresses
                        #print (yellow('- level3SL to add to level2_dict children : '+json.dumps(level3SL),bold=True))
                        list_copy = level3SL.copy()
                        level2_dict.update({"children":list_copy})
                        if level2_dict not in level2SL:     
                            dictionary_copy = level2_dict.copy()
                            level2SL.append(dictionary_copy)
                            
            #print (cyan('- level2SL to add to children : '+json.dumps(level2SL),bold=True))
            list_copy = level2SL.copy()
            level1_dict.update({"children":list_copy})
            if level1_dict not in level1SL:     
                dictionary_copy = level1_dict.copy()
                level1SL.append(dictionary_copy)              
            #print ( "==========>" )      
        level0_dict.update({"children":level1SL}) 
        #level0_dict.update({"data":data0_list})
        Main_Dict_Tree.append(level0_dict)
        object_id+=1
    for item in Main_Dict_Tree:    
        item_txt=json.dumps(item,sort_keys=True,indent=4, separators=(',', ': '))
        ##print(json.dumps(response.json(),sort_keys=True,indent=4, separators=(',', ': ')))
        text=item_txt     
        fh.write(item_txt)            
        fh.write('\n')
        ##print(green(f'ITEM = {item_txt}',bold=True))  
        #print('============')

    #print(green('- Ok Done'))
    #print(cyan('Add bottom_of_the resulting data.js file'))          
    output_file.write(text)   
    output_file.write('\n')    
    with open ('./resources/bottom_of_data_file.txt') as head_file:
        text=head_file.read()    
    output_file.write(text)         
    #print(yellow('DONE - go the [ output ] folder and open graph.html with your browser',bold=True))
    fh.close() 
       