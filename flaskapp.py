from __future__ import print_function, absolute_import, unicode_literals
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from cryptography.fernet import Fernet
from flask import *
from sqltasks import *
from otp import *
import pickle
import string
import random
import re
import os

url="reverseproxy.eastus.cloudapp.azure.com" 
app = Flask(__name__, static_url_path="")

if not "rproxyseckey" in os.environ:
	os.environ['rproxyseckey']=os.urandom(32)
app.secret_key = os.environ.get('rproxyseckey')

rp = PublicKeyCredentialRpEntity(url, "Demo server")
server = Fido2Server(rp)

if not "rproxyk1" in os.environ:
	os.environ['rproxyk1']=Fernet.generate_key()

if not "rproxyk2" in os.environ:
	os.environ['rproxyk2']=Fernet.generate_key()

	
key1=os.environ.get('rproxyk1')
key2=os.environ.get('rproxyk2')
f1=Fernet(key1)
f2=Fernet(key2)
credentials = []
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/reg")
def reg():
	return render_template("getreg.html")

@app.route("/reginit", methods=["POST"])
def reginit():
	rnum=request.form['rnum']
	rnum=rnum.strip()
	o=genOtp()
	em=getEmail(rnum)
	print(rnum)
	print(o)
	print(em)
	t1=f1.encrypt(rnum.encode()).decode()
	t2=f2.encrypt(o.encode()).decode()
	print(t1)
	print(t2)
	sendEmail(em,o)
	return render_template("otpauth.html",token1=t1,token2=t2)

@app.route("/markattendance", methods=["GET"])
def markattendance():
	classid=request.args.get('classId')
	rnum=request.cookies.get('rnum')
	return render_template("authenticate.html",rnum=rnum, cid=classid)
	
@app.route("/attendance")
def attendance():
	return render_template("authenticatelegacy.html")
	
@app.route("/markattendancelegacy", methods=["POST"])
def markattendancelegacy():
	classid=request.form['cid']
	rnum=request.form['rnum']
	resp=make_response(render_template("authenticate.html",rnum=rnum, cid=classid))
	resp.set_cookie('rnum',rnum,max_age=60*60*24*365*8)
	return resp
	
@app.route("/downloadattendance", methods=["GET"])
def downloadattendance():
	classid=request.args.get('classId')
	res=getReg_nobyclass_id(classid)
	output=make_response(res)
	output.headers["Content-Disposition"] = "attachment; filename=attendance_"+classid+".csv"
	output.headers["Content-type"] = "text/csv"
	return output
	
@app.route("/getportal")
def getportal():
	cid=random.randint(0,999999)
	return render_template("instructor.html",cid=cid)
	
@app.route("/resumeportal")
def resumeportal():
	return render_template("resumeinstructor.html")
	
@app.route("/resumeportalpage", methods=["POST"])
def resumeportalpage():
	cid=request.form['cid']
	return render_template("instructor.html",cid=cid)
	
@app.route("/otpcheck", methods=["POST"])
def otpcheck():
	otp=request.form['otp']
	t1=request.form['t1'].strip().encode()
	t2=request.form['t2'].strip().encode()
	print(t1)
	print(t2)
	rnum=f1.decrypt(t1).decode()
	cotp=f2.decrypt(t2).decode()
	if otp.strip()==cotp.strip():
		print(rnum)
		resp = make_response(render_template('register.html',rnum=rnum))
		resp.set_cookie('rnum',rnum,max_age=60*60*24*365*8)
		return resp
	else:
		return render_template("otperror.html")
	
@app.route("/success")
def success():
	return render_template("success.html")
	
@app.route("/univdb")
def univdb():
    return render_template("univdb.html")
    
@app.route("/univdbupload", methods=["POST", "GET"])
def univdbupload():
    if request.method == 'POST':
      f = request.files['file']
      k=f.read().decode().splitlines()
      for x in k:
          r=x.split(",")
          for em in r:
             em=em.strip()
             if(re.fullmatch(regex, em)):
                 print(em)
                 addStudent(em)
    return redirect("/success")

	
@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    user = request.args.get('nm')
    print(user)
    credentials=readkey(user)
    registration_data, state = server.register_begin(
        {
            "id": b"user_id",
            "name": user,
            "displayName": user,
            "icon": "https://example.com/image.png",
        },
        credentials,
        user_verification="discouraged",
        authenticator_attachment="platform",
    )

    session["state"] = state
    print("\n\n\n\n")
    print(registration_data)
    print("\n\n\n\n")
    return cbor.encode(registration_data)


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    user = request.args.get('nm')
    print(user)
    credentials=readkey(user)
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    print("clientData", client_data)
    print("AttestationObject:", att_obj)
    auth_data = server.register_complete(session["state"], client_data, att_obj)
    credentials.append(auth_data.credential_data)
    savekey(credentials,user)
    print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    return cbor.encode({"status": "OK"})


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    user = request.args.get('nm')
    print(user)
    credentials=readkey(user)

    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials)
    session["state"] = state
    return cbor.encode(auth_data)

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    user = request.args.get('nm')
    classid=request.args.get('cid')
    print(user)
    print(classid)
    credentials=readkey(user)
    if not credentials:
        abort(404)

    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]
    print("clientData", client_data)
    print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    print("ASSERTION OK")
    
    print("\n\n")
    print("Attendance marking for "+user+" in class "+classid);
    addUser(user,classid)    
    return cbor.encode({"status": "OK"})
    
def savekey(credentials,user):
	with open(user+'datafilekey.pkl','wb') as outp1:
		pickle.dump(credentials,outp1,pickle.HIGHEST_PROTOCOL)
		
def readkey(user):
	print(user)
	try:
		with open(user+'datafilekey.pkl', 'rb') as inp:
			temp = pickle.load(inp)
			print("Data read")
			#print(credentials)
			return temp
	except:
		print("no cred data")
		return []


if __name__ == "__main__":
	context = ('server.crt', 'server.key')
	app.run(ssl_context=context, debug=False, host="0.0.0.0", port=8080)
