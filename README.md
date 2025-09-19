# Coldwire-server

This is an official implementation of Coldwire protocol in Python.


# What is Coldwire messenger ?
Coldwire messenger is an end-to-end encrypted, metadata-resistant, federated messenger.
You can check official client here: [Coldwire Messenger](https://github.com/Freedom-Club-Sec/Coldwire)

# Important Notes
This implementation is mainly used for prototyping protocol changes before being implemented in the [Go implementation](https://github.com/Freedom-Club-Sec/Coldwire-server)
Therefore, you must **USE WITH CAUTION**, even  though this implementation is fine for testing and or extremely low user-base, we still **highly** recommend using the Go implementation which can be found at https://github.com/Freedom-Club-Sec/Coldwire-server

And lastly, if you do use this server for production, **DO NOT** expose the server directly to the internet! You must put it behind a web-server (e.g. Apache, or Nginx)



# Preparation
This implmentation uses Redis, install it before continuing:
```bash
sudo apt install redis-server
```


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
