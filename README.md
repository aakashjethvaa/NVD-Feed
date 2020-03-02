# NVD-Feed

## About
NVD is now offering a vulnerability data feed using the JSON format. This data feed includes both previously offered and new NVD data points.That NVD JSON feed is the subject of this coding exercise.

## Technologies Used
* Python 3.5+
* PostgreSQL 9.6+
* git
* JSON

## Source 

https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

## Steps

### Install Python3

``` 
sudo apt-get update
sudo apt-get install python3.6
python3 -V
```
### Install PostgreSQL

```
sudo apt install postgresql postgresql-contrib
sudo -u postgres psql -c "SELECT version();"
sudo su - postgres
psql
```
To log in to the PostgreSQL server as the postgres user first you need to switch to the user postgres and then you can access a PostgreSQL prompt using the psql utility:

1. Create a new PostgreSQL Role

``` sudo su - postgres -c "createuser developer"
```

2. Create a new PostgreSQL Database

``` sudo su - postgres -c "createdb nvddb" 
```

3. Grant privileges
``` sudo -u postgres psql
    grant all privileges on database nvddb to developer;
```
### Python3-pip install

```python3 -m pip install --user --upgrade pip
   python3 -m pip --version
```
### Setting up Virtual Enviroment

``` python3 -m pip install --user virtualenv
    python3 -m venv <YOUR_ENV_NAME>
    source <YOUR_ENV_NAME>/bin/activate
```
If you want to get out of the venv use  `deactivate`




