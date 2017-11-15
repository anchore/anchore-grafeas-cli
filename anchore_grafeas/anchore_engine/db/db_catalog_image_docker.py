import time

from sqlalchemy import desc

from anchore_engine import db
from anchore_engine.db import CatalogImageDocker


def update_record(record, session=None):
    if not session:
        session = db.Session

    our_result = session.query(CatalogImageDocker).filter_by(imageDigest=record['imageDigest'], userId=record['userId'], tag=record['tag'], repo=record['repo'], registry=record['registry']).first()
    if our_result:
        our_result.update(record)

    return(True)

def add_record(record, session=None):
    if not session:
        session = db.Session

    our_result = session.query(CatalogImageDocker).filter_by(imageDigest=record['imageDigest'], userId=record['userId'], tag=record['tag'], repo=record['repo'], registry=record['registry']).first()
    if not our_result:
        our_result = CatalogImageDocker(**record)
        session.add(our_result)

    return(True)

def add(imageDigest, userId, tag, registry=None, user=None, repo=None, digest=None, imageId=None, dockerfile=None, session=None):
    if not session:
        session = db.Session

    dbobj = {
        'registry':registry,
        'user':user,
        'repo':repo,
        'digest':digest,
        'imageId':imageId,
        'dockerfile':dockerfile
    }

    our_result = session.query(CatalogImageDocker).filter_by(imageDigest=imageDigest, userId=userId, tag=tag).first()
    if not our_result:
        our_result = CatalogImageDocker(imageDigest=imageDigest, userId=userId, tag=tag)
        #dbobj['created_at'] = int(time.time())

        our_result.update(dbobj)
        session.add(our_result)
    else:
        our_result.update(dbobj)

    return(True)

def update(imageDigest, userId, tag, registry=None, user=None, repo=None, digest=None, imageId=None, dockerfile=None, session=None):
    return(add(imageDigest, userId, tag, registry=registry, user=user, repo=repo, digest=digest, imageId=imageId, dockerfile=dockerfile, session=session))

def get_byfilter(userId, session=None, **kwargs):
    if not session:
        session = db.Session

    ret = []

    kwargs['userId'] = userId
    
    results = session.query(CatalogImageDocker).filter_by(**kwargs).order_by(desc(CatalogImageDocker.created_at))
    for result in results:
        dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.append(dbobj)

    return(ret)

def get_alltags(imageDigest, userId, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImageDocker).filter_by(imageDigest=imageDigest, userId=userId)
    if results:
        for result in results:
            dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            ret.append(dbobj)

    return(ret)

def get(imageDigest, userId, tag, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(CatalogImageDocker).filter_by(imageDigest=imageDigest, userId=userId, tag=tag).first()
    if result:
        dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret = dbobj

    return(ret)

def get_all(userId, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImageDocker).filter_by(userId=userId)
    if results:
        for result in results:
            dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            ret.append(dbobj)
            
    return(ret)

def delete(imageDigest, userId, tag, session=None):
    if not session:
        session = db.Session

    return(True)
