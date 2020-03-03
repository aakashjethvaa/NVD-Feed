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
```  
sudo su - postgres -c "createuser developer" 
```

2. Create a new PostgreSQL Database
```  
sudo su - postgres -c "createdb nvddb" 
```

3. Grant privileges
``` 
sudo -u postgres psql
grant all privileges on database nvddb to developer;
```
### Python3-pip install

```
python3 -m pip install --user --upgrade pip
python3 -m pip --version
```
### Setting up Virtual Enviroment

``` 
python3 -m pip install --user virtualenv
python3 -m venv <YOUR_ENV_NAME>
source <YOUR_ENV_NAME>/bin/activate
```
If you want to get out of the venv use  `deactivate`

### Steps to run the project

Extracting all the CVE from the above URL

```python3 extractdata.py```

Once the PostgreSQL has been setup by running the above install PostgreSQL commands, we would create a Database connection to the above nvddb database through python code.

```python3 db_connection.py```

This would create a Database connection to nvddb. Also I would recommend you to download pgadmin, create database connection and use that as sa tool to retrieve,analyze and query onto the data.

Once the DB connection is setup we would create database tables using ```peewee``` Peewee is ORM tool for python.
Refer the link for more details : http://docs.peewee-orm.com/en/latest/

Import all the requirements from Requirements.txt file and after that run the below command

```python3 tables.py```

Once the table is created we would run the parse.py for inserting and retrieve data into our database nvddb. Also parse.py contains a method which would collect all the json data into schema.txt for lookup and testing purpose.

```python3 parse.py```

Once we have pgadmin set up, we can run live queries to retrieve the data. We can also use our local system instead of Pgadmin. I have included **Query** named file which has list of all the query to be perform on the nvddb database

Some of the views and queries :

#### What are the top 10 most vulnerable products? (Based on the number of CVEsassociated with them on a version basis.)

```
CREATE VIEW Top10Vulnerable_Product AS
  select A.name, A.version, count(*) AS CNT
  from product as A left join cvss_product as B on A.id = B.product_id
  where A.is_vulnerable IS TRUE
  group by A.name, A.version
  order by CNT DESC
  limit 10;

SELECT * from Top10Vulnerable_Product;

```
#### Show the breakdown of the number of CVEs per whole-number score (round up)

``` 
CREATE VIEW NoOfCVEs_PerWholeNum AS 
  select ceil(impact_score_2) AS range, count(*), cve_id
  from impact
  group by ceil(impact_score_2), impact,cve_id
  order by range;

SELECT * from NoOfCVEs_PerWholeNum;

```
In this way, we can perform various queries of our database nvdb based on the ER_diagram and data available. 

### Tools used

* Microsoft Visual Studio code
* Pgadmin
* Git


Thank you...
