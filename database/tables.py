import os
print(os.getcwd())
import sys
import datetime
sys.path.append("..")
from peewee import *
from nvdfeed.database import db_connection

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

class Impact(Model):
    cve_id = ForeignKeyField(CVSS, backref='impacts')
    impact_score_2 = DoubleField(null=True)
    base_score_2 = DoubleField(null=True)
    impact_score_3 = DoubleField(null=True)
    base_score_3 = DoubleField(null=True)
    created_ts = DateTimeField(unique=True)

    def save(self, *args, **kwargs):
        self.created_ts = datetime.datetime.now()
        super(Impact, self).save(*args, **kwargs)

    class Meta:
        database = db_connection.get_db()
        db_table = 'impact'

def store_impact(cve_id, impact_score_2, base_score_2, impact_score_3, base_score_3):
    impact_score_2 = val_to_none(impact_score_2, 'double')
    impact_score_3 = val_to_none(impact_score_3, 'double')
    base_score_2 = val_to_none(base_score_2, 'double')
    base_score_3 = val_to_none(base_score_3, 'double')
    with db_connection.get_db().atomic():
        record = Impact.create(cve_id=cve_id, impact_score_2=impact_score_2, base_score_2=base_score_2, impact_score_3=impact_score_3, base_score_3=base_score_3)
        record.save()
        # print('Saved impact')

ProductCVSSProxy = DeferredThroughModel()

class Product(Model):
    """
    Product Identification
    """
    # cve_id = ForeignKeyField(CVSS, backref='prod')
    cpe22uri = TextField()
    cpe23uri = TextField()
    name = TextField()
    version = TextField()
    is_vulnerable = BooleanField(default=True)
    created_ts = DateTimeField(unique=True)
    cve_ids = ManyToManyField(CVSS, backref='products', through_model=ProductCVSSProxy)

    class Meta:
        database = db_connection.get_db()
        db_table = 'product'
        # indexes = (
        #     # create a unique on name/version
        #     (('name', 'version'), True),
        # )

    def save(self, *args, **kwargs):
        self.created_ts = datetime.datetime.now()
        super(Product, self).save(*args, **kwargs)

def store_product(cpe22uri, cpe23uri, name, version, is_vulnerable):
    with db_connection.get_db().atomic():
        record = Product.create(cpe22uri=cpe22uri, cpe23uri=cpe23uri, name=name, version=version, is_vulnerable=is_vulnerable)
        record.save()
        return record

class CVSSProduct(Model):
    # product_id = ForeignKeyField(Product, db_column='product_id',index=True)
    # cvss = ForeignKeyField(CVSS, db_column='cve_id',index=True)
    cvss = ForeignKeyField(CVSS)
    product = ForeignKeyField(Product)

    class Meta:
        database = db_connection.get_db()
        db_table = 'cvss_product'

    def save(self, *args, **kwargs):
        super(CVSSProduct, self).save(*args, **kwargs)

ProductCVSSProxy.set_model(CVSSProduct)

def store_cvss_product(cvss, product):
    with db_connection.get_db().atomic():
        record = CVSSProduct.create(cvss=cvss, product=product)
        record.save()

def create_tables(database):
    models = [CVSS,Impact,Product, CVSSProduct]
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