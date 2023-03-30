#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# (c) 2021-2023 Arnim Eijkhoudt (uforia@github.com), GPLv3
#
# Please note: the MITRE ATT&CK® framework is a registered trademark
# of MITRE. See https://attack.mitre.org/ for more information.
#
# I would like to thank MITRE for the permissive licence under which
# ATT&CK® is available.
#

import argparse
import collections
import itertools
import logging
import json
import pathlib
import pprint
import re
import requests
import shutil
import string
import sys
import urllib.request
import uvicorn
import yaml
from config import settings as options
from config.matrixtable import Matrices
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Optional


hashmap = {
    'fgdsid': 'Data Sources',
    'fgmid': 'Mitigations',
}
typemap = {
    'attack-pattern': 'Techniques',
    'case-studies': 'Case Studies',
    'campaign': 'Campaigns',
    'course-of-action': 'Mitigations',
    'data component': 'Data Sources',
    'data source': 'Data Sources',
    'detections': 'Data Sources',
    'detection-rules': 'Detections',
    'intrusion-set': 'Actors',
    'malware': 'Malwares',
    'mitigation': 'Mitigations',
    'mitigations': 'Mitigations',
    'snippets': 'Code Snippets',
    'tactic': 'Tactics',
    'tactics': 'Tactics',
    'technique': 'Techniques',
    'techniques': 'Techniques',
    'tool': 'Tools',
    'tools': 'Tools',
    'uid': 'UID',
    'x-mitre-data-component': 'Data Sources',
    'x-mitre-data-source': 'Data Sources',
    'x-mitre-tactic': 'Tactics',
}
categories=[
    'Actors',
    'Campaigns',
    'Case Studies',
    'Code Snippets',
    'Data Sources',
    'Detection Rules',
    'Malwares',
    'Matrices',
    'Mitigations',
    'Tactics',
    'Techniques',
    'Tools',
]
tags_metadata = [
    {
        'name': 'docs',
        'description': 'This documentation.',
    },
    {
        'name': 'explore',
        'description': 'Basic interface for exploring the loaded MITRE ATT&CK® matrices. Returns a raw view of everything '
                       'under *treepath*, including all empty branches. **WARNING**: Can result in a lot of output!'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/explore/Actors/G0005) '
                       'to display all information about the *Actor G0005*.',
    },
    {
        'name': 'search',
        'description': 'Does a case-insensitive *LOGICAL AND search for all params fields in all entity names, urls and '
                       'descriptions, and returns a list of matching entities in all loaded MITRE ATT&CK® matrices.'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) +
                       '/api/search?params=dragon) '
                       'to find all entities with the word *dragon*.',
    },
    {
        'name': 'actoroverlap',
        'description': 'Finds the overlapping TTPs (*Malwares, Mitigations, Techniques, etc.*) for '
                       'two actors. Returns a list of Actors, a list of matrices they were found in, and *only* the TTPs '
                       'that overlapped (with their names/descriptions). Finding the TTPs that do not overlap can be '
                       'relatively trivially done through programmatical means, by pulling the complete Actor records '
                       'using the `/explore/` API endpoint and comparing the results for every actor with the overlapping '
                       'TTPs logically (`<Overlapping TTPs> NOT <actor\'s TTPs>`) to find the remaining TTPs per actor.'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/actoroverlap?actors=G0064&actors=G0050)'
                       ' to find the overlapping TTPs of *Actors G0064* and *G0050*.',
    },
    {
        'name': 'ttpoverlap',
        'description': 'Finds all actors that have a specific set of TTPs (*Malwares, (Sub)Techniques, Techniques '
                       'and Tools*). The number of TTPs can be varied, i.e.: 1 ... n fields can be given. Returns '
                       'the matching Actors with all of their ATT&CK® entity types (including names/descriptions).'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/ttpoverlap?ttps=S0002&ttps=S0008&ttps=T1560.001) '
                       'to find which *Actors* use *Tool S0002*, *Tool S0008* and *Technique T1560.001*.',
    },
    {
        'name': 'findactor',
        'description': 'Given the set of TTPs, find out which subsets (\'slices\') of those TTPs match any known '
                       'actors. Returns an overview of potentially matching Actors, with the amount of matching and '
                       'total TTPs for that Actor. This is particularly useful if you have a TTP set that would not '
                       'match a known Actor, e.g. due to errors, incompleteness, TTPs not matching that Actor '
                       '(e.g. because of an Actor changing its TTPs), etc. This can be a somewhat resource intensive '
                       'query, especially with large TTP sets.'
                       '<br /><br />'
                       '[Example query]'
                       '(http://' + options.ip + ':' + str(options.port) + '/api/findactor?ttps=T1078&ttps=T1588.002&'
                       'ttps=S0002&ttps=S0008&ttps=S0032&ttps=T1574)'
                       ' to find which *Actors* use use *Techniques T1078, T1588.002 and T1574* and *Tools S0002, S0008'
                       ' and S0032*.',
    },
]
app = FastAPI(title='MITRE ATT&CK Matrix API', openapi_tags=tags_metadata)

@app.get('/', tags=['docs'])
async def read_root():
    return RedirectResponse('/docs')


@app.get('/api/', tags=['docs'])
async def read_api():
    return RedirectResponse('/docs')


@app.get('/api/explore/{treepath:path}', tags=['explore'])
async def query(request: Request,
                token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    try:
        results = {}
        cache = loadCache(options)
        if not request.path_params['treepath']:
            results = {
                'Metadata': {
                    'name': 'AttackMatrix API',
                    'description': 'Available keys: ' + ', '.join(key for key in cache),
                    'matrices': cache['Matrices'],
                },
            }
        else:
            treepath = request.path_params['treepath'].split('/')
            treepath = [i for i in treepath if i]
            results = cache[treepath[0]][treepath[1]] if len(treepath)>1 else cache[treepath[0]]
    except KeyError as e:
        results = {
            'error': 'Key does not exist: '+str(e),
        }
    finally:
        return JSONResponse(results)


@app.get('/api/search', tags=['search'])
async def searchParam(request: Request,
                      params: list = Query([]),
                      token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return search(options, params)

@app.get('/api/actoroverlap', tags=['actoroverlap'])
async def actorOverlap(request: Request,
                       actors: list = Query([]),
                       token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return findActorOverlap(options, actors)


@app.get('/api/ttpoverlap', tags=['ttpoverlap'])
async def ttpOverlap(request: Request,
                     ttps: list = Query([]),
                     token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return findTTPOverlap(options, ttps)


@app.get('/api/findactor', tags=['findactor'])
async def findActor(request: Request,
                     ttps: list = Query([]),
                     token: Optional[str] = None):
    if options.token:
        if token != options.token:
            raise HTTPException(status_code=403, detail='Access denied: missing or incorrect token')
    return findActorByTTPs(options, ttps)


def findActorOverlap(options, actors=[]):
    try:
        response = {}
        if not len(actors)>1:
            response = {
                'error': 'Specify at least two Actors to check for overlap!',
                'count': 0,
            }
        else:
            cache = loadCache(options)
            response = collections.defaultdict(lambda: {}, {})
            ttps = {}
            actors = [actor.upper() for actor in actors]
            # Build a list of all TTPs of all actors (OR)
            for actor in actors:
                response[actor] = {}
                if actor in cache['Actors']:
                    for category in categories:
                        if category in cache['Actors'][actor]:
                            for ttp in cache['Actors'][actor][category]:
                                if not category in ttps:
                                    ttps[category] = {}
                                ttps[category][ttp] = cache['Actors'][actor][category][ttp]
                else:
                    response = {
                        'error': 'AttackMatrix: actor '+actor+' does not exist!',
                        'count': 0,
                    }
                    return response
            # Wipe TTP categories and types that do not appear in all actors
            commonttps = {}
            for ttpcategory in ttps:
                commonttps[ttpcategory] = {}
                for ttp in ttps[ttpcategory]:
                    # First, assume the TTP is valid
                    exists = True
                    for actor in actors:
                        if not ttpcategory in cache['Actors'][actor]:
                            # If the TTP category does not exist for that actor, it is not a valid TTP
                            exists = False
                        else:
                            if not ttp in cache['Actors'][actor][ttpcategory]:
                                # If the TTP does not exist for an actor, it is not a valid TTP
                                exists = False
                    if exists:
                        commonttps[ttpcategory][ttp] = cache['Actors'][actor][ttpcategory][ttp]
            count = 0
            for actor in actors:
                for ttpcategory in commonttps:
                    if len(commonttps[ttpcategory])>0:
                        response[actor][ttpcategory] = commonttps[ttpcategory]
                        count += len(commonttps[ttpcategory])
                response[actor]['Metadata'] = cache['Actors'][actor]['Metadata']
            response['count'] = count/len(actors)
    except Exception as e:
        response = {
            'error': 'Python Error: '+str(type(e))+': '+str(e),
            'count': 0,
        }
    finally:
        return response


def findTTPOverlap(options, ttps=[]):
    try:
        response = {}
        if not len(ttps)>1:
            response = {
                'error': 'Specify at least two TTPs to check for overlap!',
                'count': 0,
            }
        else:
            cache = loadCache(options)
            response = {}
            ttps = [ttp.upper() for ttp in ttps]
            for actor in cache['Actors']:
                actorttps = []
                response[actor] = {}
                for category in categories:
                    if category in cache['Actors'][actor]:
                        actorttps += list(cache['Actors'][actor][category])
                if set(ttps).issubset(actorttps):
                    response[actor] = cache['Actors'][actor]
                else:
                    del response[actor]
    except Exception as e:
        response = {
            'error': 'Python Error: '+str(type(e))+': '+str(e),
            'count': 0,
        }
    finally:
        return response


def findActorByTTPs(options, ttps=[]):
    try:
        response = {}
        if not len(ttps)>2:
            response = {
                'error': 'Specify at least three TTPs to search for matching Actors!',
                'count': 0,
            }
        else:
            cache = loadCache(options)
            response = collections.OrderedDict()
            ttps = [ttp.upper() for ttp in ttps]
            num_given_ttps = len(ttps)
            slices = list(reversed([_ for _ in sorted(list(map(ttps.__getitem__, itertools.starmap(slice, itertools.combinations(range(len(ttps)+1), 2)))), key=len) if len(_)>2]))
            if len(slices):
                for subset in slices:
                    searchterms = '&ttps='.join([urllib.parse.quote(_) for _ in subset])
                    if re.search(r"[\w\s,.\+\-]+", searchterms):
                        result = findTTPOverlap(options,subset)
                        if len(result):
                            for actor in result.keys():
                                if not actor in response:
                                    num_known_ttps = 0
                                    for category in categories:
                                        if category in result[actor]:
                                            num_known_ttps += len(result[actor][category])
                                    response[actor] = {
                                        'id': actor,
                                        'name': ', '.join(result[actor]['Metadata']['name']),
                                        'matching_ttps': subset,
                                        'num_matching_ttps': len(subset),
                                        'num_given_ttps': num_given_ttps,
                                        'num_known_ttps': num_known_ttps,
                                        'matching_coverage': '%.2f' % ((len(subset)/num_given_ttps)*100) + '%',
                                        'total_coverage': '%.2f' % ((len(subset)/num_known_ttps)*100) + '%'
                                    }
                                else:
                                    if len(subset) > response[actor]['num_matching_ttps']:
                                        response[actor] = {
                                            'id': actor,
                                            'name': ', '.join(result[actor]['Metadata']['name']),
                                            'matching_ttps': subset,
                                            'num_matching_ttps': len(subset),
                                            'num_given_ttps': num_given_ttps,
                                            'num_known_ttps': num_known_ttps,
                                            'matching_coverage': '%.2f' % ((len(subset)/num_given_ttps)*100) + '%',
                                            'total_coverage': '%.2f' % ((len(subset)/num_known_ttps)*100) + '%'
                                        }
            if len(response):
                response['count'] = len(response)
                return response
    except Exception as e:
        response = {
            'error': 'Python Error: '+str(type(e))+': '+str(e),
            'count': 0,
        }
    finally:
        return response


def search(options, params=[]):
    try:
        response = {}
        if not len(params):
            response = {
                'error': 'Specify at least one search parameter!',
                'count': 0,
            }
        else:
            cache = loadCache(options)
            response = collections.defaultdict(lambda: {})
            for category in categories:
                for object in cache[category]:
                    metadata = cache[category][object]['Metadata']
                    contents = ' '.join(metadata['name'])
                    contents += ' '.join(metadata['description'])
                    contents += ' '.join(metadata['url'])
                    if all(term.lower() in contents.lower() for term in params):
                        response[category][object] = cache[category][object]
            response['count'] = sum(len(response[item]) for item in response)
    except Exception as e:
        response = {
            'error': 'Python Error: '+str(type(e))+': '+str(e),
            'count': 0,
        }
    finally:
        return response


def loadCache(options):
    cachefile = pathlib.Path(options.cachefile)
    if options.verbose:
        logging.info('Loading cache ' + cache.name + '...')
    try:
        with open(cachefile, 'r') as cache:
            return json.loads(cache.read())
    except (ValueError, FileNotFoundError):
        if options.verbose:
            logging.error('Error loading the cachefile ' + cachefile.name)


def GenerateMatrix(options):
    merged = collections.defaultdict(lambda: dict())
    for category in categories:
        merged[category] = {}
        merged[category]['UIDs'] = {}
    for matrix in Matrices:
        matrixfile = pathlib.Path(options.cachedir+'/'+Matrices[matrix]['file'])
        if not matrixfile.exists():
            # Missing ATT&CK matrix file
            continue
        else:
            matrixname = Matrices[matrix]['name']
            matrixdescription = Matrices[matrix]['description']
            matrixtype = Matrices[matrix]['type']
            matrixurl = Matrices[matrix]['url']
            merged['Matrices'][matrix] = {'Metadata': {
                    'name': [matrixname],
                    'description': [matrixdescription],
                    'url': [matrixurl],
            }}
            if matrixtype == 'unprotectit':
                with open(matrixfile, 'r') as f:
                    contents = json.loads(f.read())
                    if 'techniques' in contents:
                        objects = contents['techniques']
                try:
                    for object in objects:
                        ids = object['unprotect_id'].replace(' ','').split(',')
                        for id in ids:
                            if id.startswith('T') or id.startswith('U'):
                                objectid = str(object['id'])
                                mitreid = id
                                objectnames = []
                                objectdescriptions = []
                                objecturls = []
                                if 'name' in object:
                                    objectnames = [object['name']]
                                if 'description' in object:
                                    objectdescriptions = [object['description']]
                                for url in object['resources'].split('\r\n'):
                                    objecturls.append(url)
                                type = 'Techniques'
                                if not mitreid in merged[type]:
                                    merged[type][mitreid] = {}
                                merged[type][mitreid]['Metadata'] = {
                                    'name': objectnames,
                                    'description': objectdescriptions,
                                    'url': objecturls,
                                }
                                # Add the matrix to the ID
                                if 'Matrices' not in merged[type][mitreid]:
                                    merged[type][mitreid]['Matrices'] = {}
                                if not matrix in merged[type][mitreid]['Matrices']:
                                    merged[type][mitreid]['Matrices'][matrix] = merged['Matrices'][matrix]['Metadata']
                                # Add the UID to the list
                                merged[type]['UIDs'][mitreid] = mitreid
                                if not mitreid in merged[type]:
                                    merged[type][mitreid] = {}
                                subobject = 1
                                for snippet in object['snippets']:
                                    mitresubid = 'CS' + mitreid[1:] + '.' + str(subobject).zfill(3)
                                    type = 'Code Snippets'
                                    objectdescriptions = []
                                    if 'technique' in snippet:
                                        objecturls = [snippet['technique']]
                                    if 'description' in snippet:
                                        objectdescriptions = [object['description']]
                                    if not mitresubid in merged[type]:
                                        merged[type][mitresubid] = {}
                                    merged[type][mitresubid]['Metadata'] = {
                                        'name': objectnames,
                                        'description': objectdescriptions,
                                        'url': objecturls,
                                    }
                                    # Add the matrix to the ID
                                    if 'Matrices' not in merged[type][mitresubid]:
                                        merged[type][mitresubid]['Matrices'] = {}
                                    if not matrix in merged[type][mitresubid]['Matrices']:
                                        merged[type][mitresubid]['Matrices'][matrix] = merged['Matrices'][matrix]['Metadata']
                                    # Add the UID to the list
                                    merged[type]['UIDs'][mitresubid] = mitresubid
                                    subobject += 1
                                subobject = 1
                                for detection_rule in object['detection_rules']:
                                    mitresubid = 'DR' + mitreid[1:] + '.' + str(subobject).zfill(3)
                                    type = 'Detection Rules'
                                    objectnames = [detection_rule['type']['syntax_lang'] + ' rule for ' + detection_rule['name']]
                                    objectdescriptions = ['```'+detection_rule['type']['syntax_lang'].lower()+'\n'+detection_rule['rule']+'\n\n```\n\n']
                                    objecturls = ['https://https://unprotect.it/api/techniques/'+objectid]
                                    if not mitresubid in merged[type]:
                                        merged[type][mitresubid] = {}
                                    merged[type][mitresubid]['Metadata'] = {
                                        'name': objectnames,
                                        'description': objectdescriptions,
                                        'url': objecturls,
                                    }
                                    # Add the matrix to the ID
                                    if 'Matrices' not in merged[type][mitresubid]:
                                        merged[type][mitresubid]['Matrices'] = {}
                                    if not matrix in merged[type][mitresubid]['Matrices']:
                                        merged[type][mitresubid]['Matrices'][matrix] = merged['Matrices'][matrix]['Metadata']
                                    # Add the UID to the list
                                    merged[type]['UIDs'][mitresubid] = mitresubid
                                    subobject += 1
                            if 'attack' in mitreid:
                                print(mitreid)
                except:
                    print("Failed to parse a Unprotect.it object:")
                    pprint.pprint(object)
                    raise
            if matrixtype == 'yaml':
                with open(matrixfile, 'r') as f:
                    objects = yaml.safe_load(f.read())
                try:
                    for type in objects:
                        if type.title() in categories:
                            for object in objects[type]:
                                if object['object-type'] in typemap:
                                    type = typemap[object['object-type']]
                                    objectnames = object['name']
                                    objectdescriptions = object['description']
                                    objecturls = object['references'] if 'references' in object else [] 
                                    objectmetadata = {
                                        'name': [object['name']],
                                        'description': [object['description']],
                                        'url': objecturls,
                                    }
                                    mitreid = object['id'].lower().replace('fg','').replace('id','').upper()
                                    uid = mitreid
                                    if not mitreid in merged[type]:
                                        merged[type][mitreid] = {}
                                    if not 'Metadata' in merged[type][mitreid]:
                                        merged[type][mitreid]['Metadata'] = objectmetadata
                                    # Add the matrix to the ID
                                    if 'Matrices' not in merged[type][mitreid]:
                                        merged[type][mitreid]['Matrices'] = {}
                                    if not matrix in merged[type][mitreid]['Matrices']:
                                        merged[type][mitreid]['Matrices'][matrix] = merged['Matrices'][matrix]['Metadata']
                                    merged[type]['UIDs'][uid] = mitreid
                except:
                    print("Failed to parse a YAML object:")
                    pprint.pprint(object)
                    raise
            if matrixtype == 'stix-json':
                with open(matrixfile, 'r') as f:
                    contents = json.loads(f.read())
                    if 'objects' in contents:
                        objecttype = 'type'
                        objects = contents['objects']
                try:
                    # Create all objects
                    for object in objects:
                        if object[objecttype] in typemap:
                            type = typemap[object[objecttype]]
                            objectnames = []
                            objectdescriptions = []
                            objecturls = []
                            objectmetadata = {
                                'names': objectnames,
                                'descriptions': objectdescriptions,
                                'urls': objecturls,
                            }
                            uid = object['id']
                            mitreid = None
                            revoked = False
                            deprecated = False
                            if 'description' in object:
                                objectdescriptions.append(object['description'])
                            if 'revoked' in object:
                                revoked = object['revoked']
                            if 'x_mitre_deprecated' in object:
                                deprecated = object['x_mitre_deprecated']
                            if 'external_references' in object:
                                for external_reference in object['external_references']:
                                    if 'external_id' in external_reference:
                                        if 'mitre' in external_reference['source_name']:
                                            mitreid = external_reference['external_id']
                                            if 'name' in object:
                                                objectnames.append(object['name'])
                                            if 'aliases' in object:
                                                for alias in object['aliases']:
                                                    if alias not in objectnames:
                                                        objectnames.append(alias)
                                            if 'description' in object:
                                                if object['description'] not in objectdescriptions:
                                                    objectdescriptions.append(object['description'])
                                            if 'url' in external_reference:
                                                objecturls.append(external_reference['url'])
                            if revoked:
                                objectdescriptions.append('Note: This MITRE ID has been **revoked** and should no longer be used.\n')
                            if deprecated:
                                objectdescriptions.append('Note: This MITRE ID has been **deprecated** and should no longer be used.\n')
                            if not mitreid in merged[type]:
                                merged[type][mitreid] = {}
                            merged[type][mitreid]['Metadata'] = {
                                'name': objectnames,
                                'description': objectdescriptions,
                                'url': objecturls,
                            }
                            # Add the matrix to the ID
                            if 'Matrices' not in merged[type][mitreid]:
                                merged[type][mitreid]['Matrices'] = {}
                            if not matrix in merged[type][mitreid]['Matrices']:
                                merged[type][mitreid]['Matrices'][matrix] = merged['Matrices'][matrix]['Metadata']
                            # Add the UID to the list
                            merged[type]['UIDs'][uid] = mitreid
                except:
                    print("Failed to parse a JSON object:")
                    pprint.pprint(object)
                    raise
    # Build the relationships between MITRE IDs
    for matrix in Matrices:
        matrixfile = pathlib.Path(options.cachedir+'/'+Matrices[matrix]['file'])
        if not matrixfile.exists():
            # Missing ATT&CK matrix file
            continue
        else:
            matrixname = Matrices[matrix]['name']
            matrixdescription = Matrices[matrix]['description']
            matrixtype = Matrices[matrix]['type']
            matrixurl = Matrices[matrix]['url']
            if matrixtype == 'unprotectit':
                with open(matrixfile, 'r') as f:
                    contents = json.loads(f.read())
                    if 'techniques' in contents:
                        objects = contents['techniques']
                try:
                    # Link all objects
                    for object in objects:
                        ids = object['unprotect_id'].replace(' ','').split(',')
                        for id in ids:
                            if id.startswith('T') or id.startswith('U'):
                                try:
                                    sourcetype = 'Techniques'
                                    sourcemitreid = id
                                    source = merged[sourcetype][sourcemitreid]
                                    subobject = 1
                                    for snippet in object['snippets']:
                                        targetmitresubid = 'CS' + sourcemitreid[1:] + '.' + str(subobject).zfill(3)
                                        targettype = 'Code Snippets'
                                        subobject += 1
                                        target = merged[targettype][targetmitresubid]
                                        if not targettype in source:
                                            source[targettype] = {}
                                        source[targettype][targetmitresubid] = target['Metadata']
                                        if not sourcetype in target:
                                            target[sourcetype] = {}
                                        target[sourcetype][sourcemitreid] = source['Metadata']
                                    subobject = 1
                                    for detection_rule in object['detection_rules']:
                                        targetmitresubid = 'DR' + sourcemitreid[1:] + '.' + str(subobject).zfill(3)
                                        targettype = 'Detection Rules'
                                        subobject += 1
                                        target = merged[targettype][targetmitresubid]
                                        if not targettype in source:
                                            source[targettype] = {}
                                        source[targettype][targetmitresubid] = target['Metadata']
                                        if not sourcetype in target:
                                            target[sourcetype] = {}
                                        target[sourcetype][sourcemitreid] = source['Metadata']
                                except:
                                    print("Failed to build a relationship between:")
                                    print(sourcetype+'/'+sourcemitreid,'->',targettype+'/'+targetmitresubid)
                                    raise
                except:
                    print("Failed to parse a Unprotect.it object:")
                    pprint.pprint(object)
                    raise
            if matrixtype == 'yaml':
                with open(matrixfile, 'r') as f:
                    objects = yaml.safe_load(f.read())
                try:
                    # Link all objects
                    for type in objects:
                        if type in typemap:
                            try:
                                sourcetype = typemap[type]
                                for object in objects[type]:
                                    sourcemitreid = object['id'].upper().replace('FG','').replace('ID','')
                                    for subtree in object:
                                        if subtree in typemap:
                                            targettype = typemap[subtree]
                                            uids = object[subtree]
                                            if len(uids):
                                                for uid in uids:
                                                    if isinstance(uid,dict):
                                                        for item in uid:
                                                            if item in hashmap:
                                                                targetmitreid = uid[item].upper().replace('FG','').replace('ID','')
                                                    else:
                                                        targetmitreid = uid.upper().replace('FG','').replace('ID','')
                                                    source = merged[sourcetype][sourcemitreid]
                                                    target = merged[targettype][targetmitreid]
                                                    if not targettype in source:
                                                        source[targettype] = {}
                                                    source[targettype][targetmitreid] = target['Metadata']
                                                    if not sourcetype in target:
                                                        target[sourcetype] = {}
                                                    target[sourcetype][sourcemitreid] = source['Metadata']
                            except:
                                print("Failed to build a relationship between:")
                                print(sourcetype+'/'+sourcemitreid,'->',targettype+'/'+targetmitreid)
                                raise
                except:
                    print("Failed to parse a YAML object:")
                    pprint.pprint(object)
                    raise
            if matrixtype == 'stix-json':
                with open(matrixfile, 'r') as f:
                    objects = json.loads(f.read())['objects']
                try:
                    # Create all relationships
                    for object in objects:
                        if not object['type'] in typemap:
                            type = object['type']
                            if type == 'relationship':
                                try:
                                    sourceuid = object['source_ref']
                                    sourcemitretype = sourceuid.split('--')[0]
                                    targetuid = object['target_ref']
                                    targetmitretype = targetuid.split('--')[0]
                                    if sourcemitretype in typemap and targetmitretype in typemap:
                                        sourcetype = typemap[sourcemitretype]
                                        sourcemitreid = merged[sourcetype]['UIDs'][sourceuid]
                                        source = merged[sourcetype][sourcemitreid]
                                        targettype = typemap[targetmitretype]
                                        targetmitreid = merged[targettype]['UIDs'][targetuid]
                                        target = merged[targettype][targetmitreid]
                                        if not targettype in source:
                                            source[targettype] = {}
                                        source[targettype][targetmitreid] = target['Metadata']
                                        if not sourcetype in target:
                                            target[sourcetype] = {}
                                        target[sourcetype][sourcemitreid] = source['Metadata']
                                except KeyError:
                                    print("Failed to build a relationship between:")
                                    #print(sourcetype+'/'+sourcemitreid,'->',targettype+'/'+targetmitreid)
                                    print(sourcemitreid)
                                    pprint.pprint(source)
                                    print(targetmitreid)
                                    pprint.pprint(target)
                                    raise
                except:
                    print("Failed to parse JSON object:")
                    pprint.pprint(object)
                    raise
    for category in categories:
        if 'UIDs' in merged[category]:
            del merged[category]['UIDs']
    return merged

def DownloadMatrices(options):
    for matrix in Matrices:
        file, url = options.cachedir+'/'+Matrices[matrix]['file'], Matrices[matrix]['url']
        jsonfile = pathlib.Path(file)
        if Matrices[matrix]['type'] in ('stix-json', 'yaml'):
            if not jsonfile.exists() or options.force:
                try:
                    logging.info('Downloading ' + url)
                    with urllib.request.urlopen(url) as response, open(jsonfile, 'wb') as outfile:
                        shutil.copyfileobj(response, outfile)
                except urllib.error.HTTPError as e:
                    logging.error('Download of ' + url + ' failed: ' + e.reason)
        if Matrices[matrix]['type'] in ('unprotectit',):
            if not jsonfile.exists() or options.force:
                try:
                    page = 1
                    techniques = {'techniques': []}
                    logging.info('Downloading ' + url + ' page ' + str(page))
                    with requests.get(url, headers={'Content-Type': 'application/json'}) as response:
                        json_response = response.json()
                        if 'count' in json_response:
                            if 'results' in json_response:
                                results = json_response['results']
                                for result in results:
                                    techniques['techniques'].append(result)
                            # Grab the next pages as well (if they exist)
                            if 'next' in json_response:
                                nextpage = json_response['next']
                                while nextpage:
                                    logging.info('Downloading ' + url + ' page ' + str(nextpage))
                                    with requests.get(nextpage, headers={'Content-Type': 'application/json'}) as response:
                                        json_response = response.json()
                                        if 'count' in json_response:
                                            if 'results' in json_response:
                                                results = json_response['results']
                                                for result in results:
                                                    techniques['techniques'].append(result)
                                                if 'next' in json_response:
                                                    nextpage = json_response['next']
                    if len(techniques):
                        with open(file, mode='w') as f:
                            cache = json.dumps(techniques)
                            f.write(cache)
                            text = "Unprotect.it cache rebuilt."
                            return {'messages': [
                                {'text': text},
                            ]}
                except urllib.error.HTTPError as e:
                    logging.error('Download of ' + url + ' failed: ' + e.reason)


if __name__ == "__main__":
    '''
    Interactive run from the command-line
    '''
    parser = argparse.ArgumentParser(description='MITRE ATT&CK® Matrix parser'
                                                 ' - can be run directly to '
                                                 'provide an API or imported '
                                                 'as a module to provide a '
                                                 'Python dictionary.')
    parser.add_argument('-f', '--force',
                        dest='force',
                        action='store_true',
                        default=options.force,
                        help='[optional] Redownload the matrices and overwrite '
                             'the cache file (clean run).')
    parser.add_argument('-d', '--daemonize',
                        dest='daemonize',
                        action='store_true',
                        default=False,
                        help='[optional] Daemonize and provide an API that '
                              'can be queried via webclients to return matrix '
                              'data (see docs).')
    parser.add_argument('-i', '--ip',
                        dest='ip',
                        default=options.ip,
                        required=False,
                        help='[optional] Host the daemon should listen '
                             'on (default: ' + options.ip + ').')
    parser.add_argument('-p', '--port',
                        dest='port',
                        default=options.port,
                        required=False,
                        help='[optional] Port the daemon should listen '
                             'on (default: ' + str(options.port) + ').')
    parser.add_argument('-k', '--key',
                        dest='token',
                        default=options.token,
                        required=False,
                        help='[optional] Block all web access unless a '
                             'valid token is offered (default: ' +
                             str(options.token) + ').')
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true',
                        default=options.verbose,
                        help='[optional] Print lots of debugging and verbose '
                             'information about what\'s happening (default: '
                             'disabled).')
    parser.add_argument('-l', '--logfile',
                        dest='logfile',
                        default=options.logfile,
                        help='[optional] Logfile for log output (default: \'' +
                             options.logfile + '\')')
    parser.add_argument('-m', '--cachedir',
                        dest='cachedir',
                        default=options.cachedir,
                        help='[optional] Directory for cache (default: \'' +
                             options.cachedir + '\')')
    parser.add_argument('-c', '--cachefile',
                        dest='cachefile',
                        default=options.cachefile,
                        help='[optional] Filename for cache (default: \'' +
                             options.cachefile + '\')')
    options = parser.parse_args()
    logging.basicConfig(filename=options.logfile, level=logging.INFO)
    cachefile = pathlib.Path(options.cachefile)
    if options.force:
        if options.verbose:
            logging.info('Generating the cachefile: ' + cachefile.name)
        DownloadMatrices(options)
        cache = GenerateMatrix(options)
        with open(cachefile, 'w') as newcachefile:
            json.dump(cache, newcachefile)
    if not options.daemonize:
        parser.print_help()
    else:
        cachefile = pathlib.Path(options.cachefile)
        if not cachefile.exists():
            if options.verbose:
                logging.info('Loading the cachefile: ' + cachefile.name)
            DownloadMatrices(options)
            cache = GenerateMatrix(options)
            with open(cachefile, 'w') as cachefile:
                json.dump(cache, cachefile)
        else:
            with open(cachefile, 'r') as cachefile:
                cache = json.load(cachefile)
        try:
            port = int(options.port)
        except ValueError:
            logging.error('The listening port must be a numeric value')
        uvicorn.run('attackmatrix:app', host=options.ip, port=options.port, log_level='info', reload=True)
else:
    '''
    Module import: GenerateMatrix() to get a Python dict
    '''
