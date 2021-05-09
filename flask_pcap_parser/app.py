# -*- coding: UTF-8 -*-
from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
import os
from sqlalchemy.orm import sessionmaker
from tabledef import *
import sqlite3
from netmiko import ConnectHandler
import sys
from crayons import blue, green, yellow, white, red, cyan
from werkzeug.utils import secure_filename
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.compat import compat_ord
import struct
import csv
import datetime
import pcap_parser
import socket
import webbrowser
import threading
import time
import graph_it

engine = create_engine('sqlite:///users.db', echo=True)

UPLOAD_FOLDER = './files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','pcap'}
protocols = {"1":"ICMP","2":"GMP","4":"IPv4","6":"TCP","17":"UDP","41":"IPv6","43":"IPv6-Route","44":"IPv6-Frag","46":"RSVP","47":"GRE","50":"ESP","51":"AH","58":"IPv6-ICMP","59":"IPv6-NoNxt","60":"IPv6-Opts","88":"EIGRP","89":"OSPFIGP","94":"IPIP","112":"VRRP","115":"L2TP"}
PAGE_DESTINATION=""




def open_browser_tab(host, port):
    url = 'http://%s:%s/' % (host, port)

    def _open_tab(url):
        time.sleep(1.5)
        webbrowser.open_new_tab(url)

    thread = threading.Thread(target=_open_tab, args=(url,))
    thread.daemon = True
    thread.start()

def mac_addr(address):
    '''Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    '''
    return ':'.join('%02x' % compat_ord(b) for b in address)
    
def ip_to_str(address):
    '''
        convert a ip address into a readable / printable string
    '''
    return socket.inet_ntoa(address)
    
def data_to_db(data):
    '''
        Create a sqli database and a table named trace
        And fill it with the content of a list called data
    '''
    sql_create="CREATE TABLE IF NOT EXISTS trace ( id text PRIMARY KEY, time text, ip_source text, mac_source text, ip_destination text, mac_destination text, protocol,port_source,port_destination,length,info);"
    sql_add="INSERT OR REPLACE into trace (id, time, ip_source, mac_source,ip_destination, mac_destination, protocol ,port_source,port_destination,length,info) VALUES (?,?,?,?,?,?,?,?,?,?,?);" 
    database=os.path.join("./bases/", "trace.db")
    #with sqlite3.connect('./bases/trace.db') as conn:
    with sqlite3.connect(database) as conn:
        c=conn.cursor()
        try:
            c.execute(sql_create)
        except:
            sys.exit("couldn't create database")
        try:
            c.executemany(sql_add, data)
        except:
            sys.exit("Error adding data to db")
        return(c)
    return()    
    

def run_parser():
    print(yellow("RUN PARSER",bold=True))
    file = open(r'pcap_parser.py', 'r').read()
    return exec(file)
    
def run_grap_it():
    print(yellow("RUN GRAPH IT",bold=True))
    file = open(r'graph_it.py', 'r').read()
    return exec(file)    
    
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
           
def select_device(id):
    device=[]
    with sqlite3.connect("devices.db") as conn:
        cursor=conn.cursor()
        sql_request = "SELECT * from devices where id = 0"
        cursor.execute(sql_request)        
        for resultat in cursor:
            #print(resultat)        
            device = {
                'device_type': resultat[1],
                'ip': resultat[3],
                'username': resultat[4],
                'password': resultat[5]
            }                 
    return(device)
    
def connect(device,command):
    #connection a l ASA
    #print (device)
    net_connect = ConnectHandler(**device)
    net_connect.find_prompt()
    output = net_connect.send_command(command)
    #print (output)
    return(output)    

def get_rows_from_db(sql):
   database=os.path.join("./bases/", "trace.db")
   con = sqlite3.connect(database)
   con.row_factory = sqlite3.Row  
   cur = con.cursor()
   cur.execute(sql)   
   rows = cur.fetchall();
   return rows
   
app = Flask(__name__)
 
@app.route('/analysis')
def analysis():
   rows = get_rows_from_db("select * from trace limit 500")
   PAGE_DESTINATION="analysis"
   return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,rows = rows)
   
@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        PAGE_DESTINATION="home"
        return render_template('main_index.html',USERNAME=session['user'],PAGE_DESTINATION=PAGE_DESTINATION)        
       
@app.route('/delete_table')
def delete_table():
    PAGE_DESTINATION="delete_table"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION) 
    
@app.route('/delete_table_confirmed')
def delete_table_2():
    database=os.path.join("./bases/", "trace.db")
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row  
    cur = con.cursor()   
    sql=f"drop table trace"
    cur.execute(sql)
    sql_create="CREATE TABLE IF NOT EXISTS trace ( id text PRIMARY KEY, time text, ip_source text, mac_source text, ip_destination text, mac_destination text, protocol,port_source,port_destination,length,info);"  
    cur.execute(sql_create)
    PAGE_DESTINATION="delete_table_confirmed"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION)     
    
@app.route('/upload')
def upload():
    PAGE_DESTINATION="upload"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION)    
    

@app.route('/upload_2',methods=['GET', 'POST'])
def upload_2():
    if request.method == 'POST':
        print(yellow("OK POST",bold=True))
        # check if the post request has the file part        
        #file = request.files['file']
        #https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
        print(red(request,bold=True))
        if 'file' not in request.files:
            flash('No file part')
            print(red(f"No file part",bold=True))
            return redirect(request.url)
        file = request.files['file']
        print(yellow(f"OK POST : {file}",bold=True))
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)        
        if file and allowed_file(file.filename):
            print(yellow(f"FILE Allowed",bold=True))
            filename = secure_filename(file.filename)
            print(green(filename,bold=True))
            #file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) # for keeping original file name
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], "f.pcap"))
            PAGE_DESTINATION="upload-2"
            return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,filename=filename)     

@app.route('/search')
def search():
    database=os.path.join("./bases/", "trace.db")
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row  
    cur = con.cursor()
    cur.execute("select ip_source from trace GROUP BY ip_source ORDER BY ip_source")
    datas={}
    datas['ip_sources'] = cur.fetchall()
    '''
    for item in datas['ip_sources']:
        print(yellow(item['ip_source'],bold=True))
    '''
    cur.execute("select mac_source from trace GROUP BY mac_source ORDER BY mac_source")
    datas['mac_sources'] = cur.fetchall()
    '''
    for item in datas['mac_sources']:
        print(green(item['mac_source'],bold=True))       
    '''
    cur.execute("select ip_destination from trace GROUP BY ip_destination ORDER BY ip_destination")
    datas['ip_destinations'] = cur.fetchall()
    '''
    for item in datas['ip_destinations']:
        print(cyan(item['ip_destination'],bold=True))        
    '''
    cur.execute("select mac_destination from trace GROUP BY mac_destination ORDER BY mac_destination")
    datas['mac_destinations'] = cur.fetchall()
    '''
    for item in datas['mac_destinations']:
        print(cyan(item['mac_destination'],bold=True))   
    '''
    cur.execute("select protocol from trace GROUP BY protocol ORDER BY protocol")
    datas['protocols'] = cur.fetchall()
    '''
    for item in datas['protocols']:
        print(cyan(item['protocol'],bold=True))           
    '''
    cur.execute("select port_source from trace GROUP BY port_source ORDER BY port_source")
    datas['port_sources'] = cur.fetchall()
    '''
    for item in datas['port_sources']:
        print(cyan(item['port_source'],bold=True))   
    '''
    cur.execute("select port_destination from trace GROUP BY port_destination ORDER BY port_destination")
    datas['port_destinations'] = cur.fetchall()
    '''
    for item in datas['port_destinations']:
        print(cyan(item['port_destination'],bold=True))            
    '''
    PAGE_DESTINATION="search"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,datas=datas)  

@app.route('/search2',methods=['GET','POST'])
def search2():
    ip_source=request.form['ip_source']
    mac_source=request.form['mac_source']
    ip_destination=request.form['ip_destination']
    mac_destination=request.form['mac_destination'] 
    protocol=request.form['protocol']    
    port_destination=request.form['port_destination']
    port_source=request.form['port_source'] 
    sql=""
    sql=f"select * from trace "
    add_where=0
    if ip_source!="ALL":
        sql+=f"WHERE `ip_source` = '{ip_source}' "
        add_where=1
    if mac_source!="ALL":
        if add_where==1:
            sql+=f"AND `mac_source` = '{mac_source}' "
        else:
            sql+=f"WHERE `mac_source` = '{mac_source}' "
            add_where=1  
    if ip_destination!="ALL":
        if add_where==1:
            sql+=f"AND `ip_destination` = '{ip_destination}' "
        else:
            sql+=f"WHERE `ip_destination` = '{ip_destination}' "
            add_where=1  
    if mac_destination!="ALL":
        if add_where==1:
            sql+=f"AND `mac_destination` = '{mac_destination}' "
        else:
            sql+=f"WHERE `mac_destination` = '{mac_destination}' "
            add_where=1  
    if protocol!="ALL":
        if add_where==1:
            sql+=f"AND `protocol` = '{protocol}' "
        else:
            sql+=f"WHERE `protocol` = '{protocol}' "
            add_where=1   
    if port_source!="ALL":
        if add_where==1:
            sql+=f"AND `port_source` = '{port_source}' "
        else:
            sql+=f"WHERE `port_source` = '{port_source}' "
            add_where=1   
    if port_destination!="ALL":
        if add_where==1:
            sql+=f"AND `port_destination` = '{port_destination}' "
        else:
            sql+=f"WHERE `port_destination` = '{port_destination}' "
            add_where=1             
    #sql=f"select * from trace GROUP BY mac_destination ORDER BY time"
    print(cyan(f'sql = {sql}',bold=True))
    rows = get_rows_from_db(sql)
    PAGE_DESTINATION="analysis"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,rows = rows)
            
@app.route('/parse')
def parse():
    PAGE_DESTINATION="parse"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION)     
    
@app.route('/parsed')
def run_script():
    run_parser()
    PAGE_DESTINATION="parsed"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION)     
    
@app.route('/smart_analysis')
def smart_analysis():
    PAGE_DESTINATION="smart_analysis"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION)   

@app.route('/smart_analysis-2', methods=['POST'])
def smart_analysis2():
    focus = str(request.form['focus'])
    print(cyan(f'focus = {focus}',bold=True))
    keyword = str(request.form['keyword'])
    print(cyan(f'keyword = {keyword}',bold=True))
    database=os.path.join("./bases/", "trace.db")
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row  
    cur = con.cursor()    
    datas={}
    liste_ips=[]
    if focus=="source_ip":
        if keyword:           
            sql=f"select ip_source from trace where ip_source like '%{keyword}%' GROUP BY ip_source ORDER BY ip_source"
        else:
            sql="select ip_source from trace GROUP BY ip_source ORDER BY ip_source"
        cur.execute(sql)
        datas['ips'] = cur.fetchall()
        for item in datas['ips']:
            #print(yellow(item['ip_source'],bold=True))
            liste_ips.append(item['ip_source'])
    else:
        if keyword:
            sql=f"select ip_destination from trace where ip_destination like '%{keyword}%' GROUP BY ip_destination ORDER BY ip_destination"
        else:
            sql="select ip_destination from trace GROUP BY ip_destination ORDER BY ip_destination"
        cur.execute(sql)
        datas['ips'] = cur.fetchall()
        for item in datas['ips']:
            #print(yellow(item['ip_destination'],bold=True))
            liste_ips.append(item['ip_destination'])
    PAGE_DESTINATION="smart_analysis-2"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,focus=focus,liste_ips=liste_ips)     
    
@app.route('/smart_analysis-3', methods=['GET','POST'])
def smart_analysis3():
    print(red('analisys 3',bold=True))
    focus = str(request.form['focus'])
    ip_address=request.form['ip_address']
    print(cyan(f'focus = {focus}',bold=True))
    print(cyan(f'ip_address = {ip_address}',bold=True))
    sql=""
    sql=f"select * from trace "
    if focus=="source_ip":
        sql+=f"WHERE `ip_source` = '{ip_address}' "
        print(cyan(f'sql = {sql}',bold=True))
        rows = get_rows_from_db(sql)
        nb_rows=0
        with open('./datas/data.csv','w') as file:
            for item in rows:
                line_out=item[2]+'<br>'+item[3]+';'+item[5]+';'+item[4]+';'+item[6]+';'+str(item[8])
                #print(yellow(line_out))
                file.write(line_out)
                file.write('\n')
                nb_rows+=1           
    elif focus=="destination_ip":
        sql+=f"WHERE `ip_destination` = '{ip_address}' "           
        print(cyan(f'sql = {sql}',bold=True))
        rows = get_rows_from_db(sql)
        nb_rows=0
        with open('./datas/data.csv','w') as file:
            for item in rows:
                line_out=item[4]+'<br>'+item[3]+';'+item[5]+';'+item[2]+';'+item[6]+';'+str(item[8])
                #print(yellow(line_out))
                file.write(line_out)
                file.write('\n')
                nb_rows+=1     
    if nb_rows>1:
        if focus=="source_ip":
            print(red("here"))
            run_grap_it() 
            database=os.path.join("./bases/", "trace.db")
            con = sqlite3.connect(database)
            con.row_factory = sqlite3.Row  
            cur = con.cursor()      
            sql=f"select ip_source from trace where ip_source = '{ip_address}' GROUP BY ip_source ORDER BY ip_source"
            cur.execute(sql)
            datas={}
            datas['ip_sources'] = cur.fetchall()
            '''
            for item in datas['ip_sources']:
                print(yellow(item['ip_source'],bold=True))
            '''
            sql=f"select mac_source from trace where ip_source = '{ip_address}' GROUP BY mac_source ORDER BY mac_source"
            cur.execute(sql)
            datas['mac_sources'] = cur.fetchall()
            '''
            for item in datas['mac_sources']:
                print(green(item['mac_source'],bold=True))       
            '''
            sql=f"select ip_destination from trace where ip_source = '{ip_address}' GROUP BY ip_destination ORDER BY ip_destination"
            cur.execute(sql)
            datas['ip_destinations'] = cur.fetchall()
            '''
            for item in datas['ip_destinations']:
                print(cyan(item['ip_destination'],bold=True))     
            '''
            sql=f"select mac_destination from trace where ip_source = '{ip_address}'  GROUP BY mac_destination ORDER BY mac_destination"
            cur.execute(sql)
            datas['mac_destinations'] = cur.fetchall()
            '''
            for item in datas['mac_destinations']:
                print(cyan(item['mac_destination'],bold=True))
            '''
            sql=f"select protocol from trace where ip_source = '{ip_address}'  GROUP BY protocol ORDER BY protocol"
            cur.execute(sql)
            datas['protocols'] = cur.fetchall()
            '''
            for item in datas['protocols']:
                print(cyan(item['protocol'],bold=True))  
            '''
            sql=f"select port_source from trace where ip_source = '{ip_address}'  GROUP BY port_source ORDER BY port_source"
            cur.execute(sql)
            datas['port_sources'] = cur.fetchall()
            '''
            for item in datas['port_sources']:
                print(cyan(item['port_source'],bold=True))
            '''
            sql=f"select port_destination from trace where ip_source = '{ip_address}'  GROUP BY port_destination ORDER BY port_destination"
            cur.execute(sql)
            datas['port_destinations'] = cur.fetchall()
            '''
            for item in datas['port_destinations']:
                print(cyan(item['port_destination'],bold=True))         
            '''
        else:
            print(red("here"))
            run_grap_it() 
            database=os.path.join("./bases/", "trace.db")
            con = sqlite3.connect(database)
            con.row_factory = sqlite3.Row  
            cur = con.cursor()      
            sql=f"select ip_source from trace where ip_destination = '{ip_address}' GROUP BY ip_source ORDER BY ip_destination"
            cur.execute(sql)
            datas={}
            datas['ip_sources'] = cur.fetchall()
            '''
            for item in datas['ip_destinations']:
                print(yellow(item['ip_destination'],bold=True))
            '''
            sql=f"select mac_source from trace where ip_destination = '{ip_address}' GROUP BY mac_source ORDER BY mac_source"
            cur.execute(sql)
            datas['mac_sources'] = cur.fetchall()
            '''
            for item in datas['mac_sources']:
                print(green(item['mac_source'],bold=True))       
            '''
            sql=f"select ip_destination from trace where ip_destination = '{ip_address}' GROUP BY ip_destination ORDER BY ip_destination"
            cur.execute(sql)
            datas['ip_destinations'] = cur.fetchall()
            '''
            for item in datas['ip_destinations']:
                print(cyan(item['ip_destination'],bold=True))     
            '''
            sql=f"select mac_destination from trace where ip_destination = '{ip_address}'  GROUP BY mac_destination ORDER BY mac_destination"
            cur.execute(sql)
            datas['mac_destinations'] = cur.fetchall()
            '''
            for item in datas['mac_destinations']:
                print(cyan(item['mac_destination'],bold=True))
            '''
            sql=f"select protocol from trace where ip_destination = '{ip_address}'  GROUP BY protocol ORDER BY protocol"
            cur.execute(sql)
            datas['protocols'] = cur.fetchall()
            '''
            for item in datas['protocols']:
                print(cyan(item['protocol'],bold=True))  
            '''
            sql=f"select port_source from trace where ip_destination = '{ip_address}'  GROUP BY port_source ORDER BY port_source"
            cur.execute(sql)
            datas['port_sources'] = cur.fetchall()
            '''
            for item in datas['port_sources']:
                print(cyan(item['port_source'],bold=True))
            '''
            sql=f"select port_destination from trace where ip_destination = '{ip_address}'  GROUP BY port_destination ORDER BY port_destination"
            cur.execute(sql)
            datas['port_destinations'] = cur.fetchall()
            '''
            for item in datas['port_destinations']:
                print(cyan(item['port_destination'],bold=True))         
            '''
        
        PAGE_DESTINATION="smart_analysis-3"
        return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,rows = rows,datas=datas,ip_address=ip_address)   
    else:
        print(cyan("not here"))
        PAGE_DESTINATION="smart_analysis-3b"
        return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION,rows = rows,ip_address=ip_address)          
@app.route('/graph', methods=['GET','POST'])
def graph():
    #run_grap_it()
    PAGE_DESTINATION="graph"
    return render_template('main_index.html',PAGE_DESTINATION=PAGE_DESTINATION)  
    
@app.route('/display_graph', methods=['GET','POST'])
def display_graph():
    return render_template('graph.html',PAGE_DESTINATION=PAGE_DESTINATION)      
    
@app.route('/login', methods=['POST'])
def do_admin_login():
 
    POST_USERNAME = str(request.form['username'])
    POST_PASSWORD = str(request.form['password'])
 
    Session = sessionmaker(bind=engine)
    s = Session()
    query = s.query(User).filter(User.username.in_([POST_USERNAME]), User.password.in_([POST_PASSWORD]) )
    result = query.first()
    if result:
        session['logged_in'] = True
        session['user'] = POST_USERNAME
    else:
        flash('wrong password!')
    return home()
  
@app.route("/logout")
def logout():
    session['logged_in'] = False
    return home()    
    
@app.route('/test', methods=['GET'])
def test():
    if session['user']== "admin":
        return render_template('test.html')    
    else:
        return render_template('deny.html',USERNAME=session['user'])

@app.route('/rooms', methods=['GET'])
def rooms():
    if session['logged_in'] == True and session['user']== "admin":
        room = str(request.args['room'])
        print()
        print(cyan('Book Room',bold=True))
        print(cyan('The Room Is : '+room,bold=True))     
        print()    
        return render_template('RoomBookingSDA.html',ROOM=room)
    else:
        return render_template('login.html')
        
if __name__ == "__main__":
    host="127.0.0.1"
    port=5000
    open_browser_tab(host,port)
    app.secret_key = os.urandom(12)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
    app.run(debug=False,host='0.0.0.0', port=5000)