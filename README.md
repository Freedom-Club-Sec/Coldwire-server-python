# Coldwire-server

This is the official Python server implementation for Coldwire secure messanger

# What is Coldwire messenger ?
Coldwire messenger is an end-to-end encrypted, metadata-resistant, federated messenger.
You can check official client here: (https://github.com/Freedom-Club-Sec/Coldwire)[Coldwire Messenger]


# Important Notes
We believe this server implementation should be OK for production, but it's important to note that this implementation may be susceptible to Denial-of-Service attacks, 
you can mitigate most of the risk by using a DDoS mitigation solutions like Cloudflare, or similar.

Additionally, you must set up HTTPS properly for your server. We recommend using Let's Encrypt project, but any other CA is fine too.
Additionally, we recommend you to block HTTP ports (80, 8080, etc) to prevent HTTP Downgrading attacks.

Using HTTPS is important for federation security, if you disable federation in the configuration file, it might be fine to operate without a certificate. (Highly unrecommended though)

And lastly, DO NOT expose the server directly to the internet! You must put it behind a web-server (e.g. Apache, or Nginx)



# Setup
Install liboqs-python:
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
cd
```


Then clone the repository:
```bash
git clone --depth 1 https://github.com/Freedom-Club-Sec/Coldwire-server.git
```

Install requirements.txt:
```bash
pip install -r requirements.txt
```

Generate new JWT Secret:
```
echo -n "JWT_SECRET=" > .env && openssl rand -base64 64 | tr -d '\n' >> .env
```

Modify `app/config.json`:
```
nano app/config.json
```
Put your server's domain name (**without http/s prefixes**) or IP address in `YOUR_DOMAIN_OR_IP`

Optionally enable or disable federation support by setting `federation` to either `true` or `false`

Run the server:
```bash
python3 run.py --host 127.0.0.1 --port 8000 --workers 4
```
