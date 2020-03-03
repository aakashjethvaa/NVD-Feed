import os
print(os.getcwd())
import sys
import datetime
sys.path.append("..")
from peewee import *
from database import db_connection

class CVSS(Model):

    cve_id = CharField(unique=True, index=True, primary_key=True)
    description = TextField()
    published_date = DateTimeField()
    last_modified_date = DateTimeField()
    created_ts = DateTimeField()

    def save(self, *args, **kwargs):
        self.created_ts = datetime.datetime.now()
        super(CVSS, self).save(*args, **kwargs)

    class Meta:
        database = db_connection.get_db()
        db_table = "cvss"

def store_cvss(cve_id, description, published_date, last_modified_date):
    with db_connection.get_db().atomic():
        record = CVSS.create(cve_id=cve_id, description=description, published_date=published_date, last_modified_date=last_modified_date)
        record.save()
        # print('Saved cvss')
        return record

def create_tables(database):
    models = [CVSS]
    with database.atomic():
        database.drop_tables(list(reversed(models)), safe=True)
        print('creating')
        for model in models:
            print(model)
            model.create_table()

def val_to_none(val,type):
    # print('value is ' + str(val))
    if val == '' or val == ' ':
        if type == 'string':
            return None
        if type == 'int':
            return None
        if type == 'double':
            return None
    return val

if __name__== "__main__":
    # print('before')
    # ProductCVSSProxy = Proxy()
    # print('after1')
    # ProductCVSSProxy.initialize(CVSSProduct)
    # print('after2')
    create_tables(db_connection.get_db())