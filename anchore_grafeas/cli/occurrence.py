import sys
import os
import re
import json
import click
import logging
import datetime

import anchore_grafeas.cli.utils

import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport
from anchore_engine.db import DistroMapping
from anchore_engine.db import Vulnerability, FixedArtifact, VulnerableArtifact, ImagePackage, ImagePackageVulnerability

import anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client
from anchore_grafeas.cli.utils import session_scope

config = {}
_logger = logging.getLogger(__name__)

@click.group(name='occurrence', short_help='Occurrence operations')
@click.pass_obj
def occurrence(ctx_config):
    global config
    config = ctx_config

@occurrence.command(name='package-vulnerabilities', short_help="Extract package-vulnerability occurrences from anchore engine DB")
@click.argument('input_image_package', nargs=-1)
def package_vulnerabilities(input_image_package):
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
        if input_image_package:
            if len(input_image_package) != 3:
                raise Exception("must supply <imageId> <packageName> <vulnerabilityId>")
            try:
                img_id_set = input_image_package[0]
            except:
                img_id_set = None
            try:
                pkg_name_set = input_image_package[1]
            except:
                pkg_name_set = None

            try:
                vuln_id_set = input_image_package[2]
            except:
                vuln_id_set = None
        else:
            img_id_set = pkg_name_set = vuln_id_set = None

        try:
            try:
                grafeas_hostport = os.environ["GRAFEAS_HOSTPORT"] #"192.168.1.3:8080"
            except Exception as err:
                raise Exception("set GRAFEAS_HOSTPORT to valid and populated grafeas <host:port>")

            _logger.debug("setting up grafeas api client for hostport: " + str(grafeas_hostport))
            api_client = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
            api_instance = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)

            print_image_vulnerability_occurrences(api_instance, img_id_set=img_id_set, pkg_name_set=pkg_name_set, vuln_id_set=vuln_id_set)
            pass
        except Exception as err:
            _logger.error("unable to populate notes - exception: " + str(err))        
            raise err
    except Exception as err:
        raise err

    anchore_grafeas.cli.utils.doexit(ecode)

#########################################################3

def make_image_vulnerability_occurrence(imageId, anch_img_pkgs, dbsession=None, gapi=None):
    import uuid

    newoccs = {}

    resource_url = None
    note_name = None

    vulnerability_details = {}

    # TODO this needs to be something meaningful
    resource_url = "N/A"

    projects_id = "anchore-vulnerabilities"

    for anch_img_pkg in anch_img_pkgs:
        try:
            p = dbsession.query(ImagePackage).filter_by(image_id=imageId, name=anch_img_pkg.pkg_name, version=anch_img_pkg.pkg_version).all()[0]
            pkgName = p.name
            pkgVersion = p.version
            pkgFullVersion = p.fullversion
            pkgRelease = p.release
        except:
            pkgName = anch_img_pkg.pkg_name
            pkgVersion = anch_img_pkg.pkg_version
            pkgFullVersion = anch_img.pkg.pkg_version
            pkgRelease = None

        distro,distro_version = anch_img_pkg.vulnerability_namespace_name.split(":",1)
        distro_cpe = "cpe:/o:"+distro+":"+distro+"_linux:"+distro_version

        note_name = "projects/anchore-vulnerabilities/notes/"+anch_img_pkg.vulnerability_id
        severity = "UNKNOWN"
        cvss_score = 0.0

        fixed_location = None
        try:
            api_response = gapi.get_note(projects_id, anch_img_pkg.vulnerability_id)
            vulnerability_note = api_response
            severity = vulnerability_note.vulnerability_type.severity
            cvss_score = vulnerability_note.vulnerability_type.cvss_score
            fix_package = fix_version = "N/A"
            for detail in vulnerability_note.vulnerability_type.details:
                if detail.cpe_uri == distro_cpe:
                    fixed_location = detail.fixed_location
                    fixed_location.package = pkgName
                    break

        except Exception as err:
            _logger.warn("could not get vulnability note from grafeas associated with found vulnerability ("+str(anch_img_pkg.vulnerability_id)+") - exception: " + str(err))

        affected_location = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityLocation(
            package=pkgName,
            version=anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=pkgFullVersion),
            cpe_uri="cpe:/a:"+anch_img_pkg.pkg_name+":"+anch_img_pkg.pkg_name+":"+anch_img_pkg.pkg_version
        )

        vulnerability_details = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityDetails(
            type=anch_img_pkg.pkg_type.upper(),
            severity=severity,
            cvss_score=cvss_score,
            fixed_location=fixed_location,
            affected_location=affected_location
        )
            

        occ_id = str(uuid.uuid4())

        occ_id = str(imageId + anch_img_pkg.pkg_name + anch_img_pkg.vulnerability_id)
        newocc = anchore_grafeas.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Occurrence(
            name='projects/anchore-vulnerability-scan/occurrences/'+str(occ_id),
            resource_url=resource_url,
            note_name=note_name,
            kind="PACKAGE_VULNERABILITY",
            vulnerability_details=vulnerability_details,
            create_time=str(datetime.datetime.utcnow()),
            update_time=str(datetime.datetime.utcnow())
        )

        newoccs[occ_id] = newocc

    return(newoccs)


def print_image_vulnerability_occurrences(gapi, img_id_set=None, pkg_name_set=None, vuln_id_set=None):
    global grafeas_hostport, myconfig

    list_only = False
    anch_img_pkgs = {}
    db_imgs = []
    with session_scope() as dbsession:
        if img_id_set:
            _logger.debug("fetching limited package set from anchore DB: " + str(img_id_set))
            try:
                dbfilter = {
                    'pkg_image_id': img_id_set,
                    'pkg_name': pkg_name_set,
                    'vulnerability_id': vuln_id_set
                }
                #p = dbsession.query(ImagePackageVulnerability).filter_by(pkg_image_id=img_).all()
                p = dbsession.query(ImagePackageVulnerability).filter_by(pkg_image_id=img_id_set, pkg_name=pkg_name_set, vulnerability_id=vuln_id_set).all()
                if p[0].pkg_image_id:
                    db_imgs = db_imgs + p
            except Exception as err:
                _logger.warn("configured image name set ("+str(img_id_set)+") not found in DB, skipping: " + str(err))
        else:
            _logger.debug("fetching full package set from anchore DB")
            db_imgs = dbsession.query(ImagePackageVulnerability).all()
            list_only = True
    
        for i in db_imgs:
            if i.pkg_image_id not in anch_img_pkgs:
                anch_img_pkgs[i.pkg_image_id] = []
            anch_img_pkgs[i.pkg_image_id].append(i)

        for imageId in anch_img_pkgs.keys():
            try:
                if list_only:
                    for el in anch_img_pkgs[imageId]:
                        print imageId + " " + el.pkg_name + " " + el.vulnerability_id
                        #print el
                else:
                    gnotes = make_image_vulnerability_occurrence(imageId, anch_img_pkgs[imageId], dbsession=dbsession, gapi=gapi)
                    for note_id in gnotes.keys():
                        gnote = gnotes[note_id]
                        print json.dumps(gnote.to_dict(), indent=4)

                    #print json.dumps(output, indent=4)
                    #projects_id = "anchore-vulnerability-scan"
                    #note = gnote

                    #always_update = False
                    #if 'always_update' in myconfig and myconfig['always_update']:
                    #    always_update = True

                    #try:
                    #    upsert_grafeas_occurrence(gapi, projects_id, note_id, gnote, always_update=always_update)
                    #except Exception as err:
                    #    _logger.warn("occurrence upsert failed - exception: " + str(err))

            except Exception as err:
                _logger.warn("unable to marshal occurrence "+str(imageId)+" into vulnerability occurrence - exception: " + str(err))            
        

    return(True)
