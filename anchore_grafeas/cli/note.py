import sys
import os
import re
import click
import logging
import copy
import threading
import time
import traceback
import datetime
import json

import anchore_grafeas.cli.utils
from anchore_grafeas.cli.utils import session_scope
import anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client

from anchore_grafeas.anchore_engine.db import ImagePackage, Vulnerability

config = {}
_logger = logging.getLogger(__name__)

@click.group(name='note', short_help='Note operations')
@click.pass_obj
def note(ctx_config):
    global config
    config = ctx_config

@note.command(name='packages', short_help="Extract package notes from anchore engine DB")
@click.argument('input_packages', nargs=-1)
def packages(input_packages):
    """
    """
    ecode = 0

    pkg_name_set = None

    try:
        db_connect = os.environ["ANCHORE_DB_CONNECT"]
        anchore_grafeas.cli.utils.do_dbconnect(db_connect)
    except Exception as err:
        raise Exception ("set ANCHORE_DB_CONNECT to a correct anchore-engine DB connect string - exception: " + str(err))

    try:
        if input_packages:
            if len(input_packages) > 1:
                raise Exception("must supply only one package or none to get a list of available package names") 
            pkg_name_set = list(input_packages)
        else:
            pkg_name_set = None

        try:
            print_package_notes(pkg_name_set=pkg_name_set)
            pass
        except Exception as err:
            _logger.error("unable to populate notes - exception: " + str(err))        
            raise err
    except Exception as err:
        raise err

    anchore_grafeas.cli.utils.doexit(ecode)

@note.command(name='vulnerabilities', short_help="Extract vulnerability notes from anchore engine DB")
@click.argument('input_vulnerabilities', nargs=-1)
def vulnerabilities(input_vulnerabilities):
    """
    """
    ecode = 0

    pkg_name_set = None

    try:
        db_connect = os.environ["ANCHORE_DB_CONNECT"]
        anchore_grafeas.cli.utils.do_dbconnect(db_connect)
    except Exception as err:
        raise Exception ("set ANCHORE_DB_CONNECT to a correct anchore-engine DB connect string - exception: " + str(err))

    try:
        if input_vulnerabilities:
            if len(input_vulnerabilities) > 1:
                raise Exception("must supply only one vulnerability or none to get a list of available vulnerability names") 
            pkg_name_set = list(input_vulnerabilities)
        else:
            pkg_name_set = None

        try:
            print_vulnerability_notes(cve_id_set=pkg_name_set)
            pass
        except Exception as err:
            _logger.error("unable to populate notes - exception: " + str(err))        
            raise err
    except Exception as err:
        raise err

    anchore_grafeas.cli.utils.doexit(ecode)

#######################################################################

def make_package_note(pkgName, anch_pkgs):
    distributions = []
    long_description = "N/A"
    external_urls = []

    for anch_pkg in anch_pkgs:
        retel = {
            'cpe_uri': None,
            'architecture': None,
            'latest_version': None,
            'maintainer': None,
            'url': None,
            'description': None
        }

        retel['cpe_uri'] = "cpe:/a:"+pkgName+":"+pkgName+":"+anch_pkg.version

        retel['architecture'] = anch_pkg.arch
        if retel['architecture'] in ['amd64', 'x86_64']:
            retel['architecture'] = 'X86'
        else:
            retel['architecture'] = 'UNKNOWN'

        retel['maintainer'] = anch_pkg.origin
        retel['latest_version'] = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=anch_pkg.fullversion)
        retel['description'] = "distro="+anch_pkg.distro_name+" distro_version="+anch_pkg.distro_version+" pkg_type="+anch_pkg.pkg_type.upper()+" license="+anch_pkg.license+" src_package="+anch_pkg.src_pkg
        retel['url'] = "N/A"

        dist = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Distribution(**retel)
        distributions.append(dist)
    
    package = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Package(name=pkgName, distribution=distributions)

    newnote = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Note(
        name="projects/anchore-distro-packages/notes/"+pkgName, 
        short_description=pkgName,
        long_description=long_description,
        related_url=external_urls,
        kind="PACKAGE_MANAGER",
        create_time=str(datetime.datetime.utcnow()),
        update_time=str(datetime.datetime.utcnow()),
        package=package
    )    
    return(newnote)

def print_package_notes(pkg_name_set=[]):
    list_only = False
    anch_pkgs = {}
    db_pkgs = []
    with session_scope() as dbsession:
        if pkg_name_set:
            _logger.debug("fetching limited package set from anchore DB: " + str(pkg_name_set))
            for pkgName in pkg_name_set:
                try:
                    p = dbsession.query(ImagePackage).filter_by(name=pkgName).all()
                    if p[0].name:
                        db_pkgs = db_pkgs + p
                except Exception as err:
                    _logger.warn("configured pkg name set ("+str(pkgName)+") not found in DB, skipping: " + str(err))
        else:
            _logger.debug("fetching full package set from anchore DB")
            db_pkgs = dbsession.query(ImagePackage).all()
            list_only = True
    
        for p in db_pkgs:
            if p.name not in anch_pkgs:
                anch_pkgs[p.name] = []
            anch_pkgs[p.name].append(p)

        for pkgName in anch_pkgs.keys():
            try:
                if list_only:
                    print pkgName
                else:
                    gnote = make_package_note(pkgName, anch_pkgs[pkgName])
                    print json.dumps(gnote.to_dict(), indent=4)

            except Exception as err:
                _logger.warn("unable to marshal package "+str(pkgName)+" into package note - exception: " + str(err))

    return(True)

def make_vulnerability_note(cveId, anch_vulns):
    nistInfo = "N/A"
    cvss_score = 0.0
    severity = "UNKNOWN"
    vulnerability_details = []
    external_urls = []
    links = []
    package_type = "N/A"
    long_description = "N/A"

    for anch_vuln in anch_vulns:
        try:
            cvss_score = anch_vuln.cvss2_score
            severity = anch_vuln.severity.upper()
            if severity == 'NEGLIGIBLE':
                severity = 'MINIMAL'

            retel = {
                'cpe_uri': None,
                'package': None,
                'severity_name': None,
                'description': None,
                'min_affected_version': None,
                'max_affected_version': None,
                'fixed_location': None
            }
            distro, distrovers = anch_vuln.namespace_name.split(":", 1)
            retel['cpe_uri'] = "cpe:/o:"+distro+":"+distro+"_linux:"+distrovers
            retel['min_affected_version'] = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind='MINIMUM')
            retel['severity_name'] = anch_vuln.severity.upper()
            if retel['severity_name'] == 'NEGLIGIBLE':
                retel['severity_name'] = 'MINIMAL'

            retel['description'] = anch_vuln.description
            long_description = anch_vuln.description
            if anch_vuln.link not in links:
                links.append(anch_vuln.link)

            for fixedIn in anch_vuln.fixed_in:
                retel['package'] = fixedIn.name
                package_type = fixedIn.version_format

                # TODO - for vulns that are present that have no fix version, unclear what to set ("MAXIMUM"?)
                if fixedIn.version and fixedIn.version != "None":
                    fix_version = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=fixedIn.epochless_version)
                else:
                    fix_version = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="MAXIMUM")

                retel['fixed_location'] = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityLocation(cpe_uri=retel['cpe_uri'], package=retel['package'], version=fix_version)

                detail = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Detail(**retel)
                vulnerability_details.append(detail)
        except Exception as err:
            _logger.warn("not enough info for detail creation - exception: " + str(err))
    
    vulnerability_type = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityType(
        cvss_score=cvss_score,
        severity=severity,
        details=vulnerability_details,
        package_type=package_type
    )

    for link in links:
        external_urls.append(anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.RelatedUrl(url=link, label="More Info"))

    newnote = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Note(
        name="projects/anchore-vulnerabilities/notes/"+cveId, 
        short_description=cveId,
        long_description=long_description,
        related_url=external_urls,
        kind="PACKAGE_VULNERABILITY",
        create_time=str(datetime.datetime.utcnow()),
        update_time=str(datetime.datetime.utcnow()),
        vulnerability_type=vulnerability_type
    )

    return(newnote)
    
def print_vulnerability_notes(cve_id_set=[]):
    list_only = False
    anchore_vulns = {}
    db_vulns = []

    with session_scope() as dbsession:
        if cve_id_set:
            _logger.debug("fetching limited vulnerability set from anchore DB: " + str(cve_id_set))
            for cveId in cve_id_set:
                try:
                    v = dbsession.query(Vulnerability).filter_by(id=cveId).all()
                    if v[0].id:
                        db_vulns = db_vulns + v
                except Exception as err:
                    _logger.warn("configured cve id set ("+str(cveId)+") not found in DB, skipping: " + str(err))
        else:
            _logger.debug("fetching full vulnerability set from anchore DB")
            db_vulns = dbsession.query(Vulnerability).all()
            list_only = True

        for v in db_vulns:
            cveId = v.id
            if v.id not in anchore_vulns:
                anchore_vulns[v.id] = []
            anchore_vulns[v.id].append(v)

        for cveId in anchore_vulns.keys():
            try:
                if list_only:
                    print cveId
                else:
                    gnote = make_vulnerability_note(cveId, anchore_vulns[cveId])
                    print json.dumps(gnote.to_dict(), indent=4)

            except Exception as err:
                _logger.warn("unable to marshal cve id "+str(cveId)+" into vulnerability note - exception: " + str(err))

    return(True)
