import os
import click
import subprocess
import sys
import logging

import note, occurrence
from anchore_grafeas import version
#import anchore_grafeas.clients

#from anchoreservice.subsys import logger

@click.group()
@click.option('--debug', is_flag=True, help='Debug output to stderr')
#@click.option('--json', is_flag=True, help='Output raw API JSON')

@click.version_option(version=version.version)
@click.pass_context
#@extended_help_option(extended_help="extended help")
def main_entry(ctx, debug):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    config = {}
    ctx.obj = config

main_entry.add_command(note.note)
main_entry.add_command(occurrence.occurrence)
#main_entry.add_command(evaluate.evaluate)
#main_entry.add_command(policy.policy)
#main_entry.add_command(subscription.subscription)
#main_entry.add_command(registry.registry)
#main_entry.add_command(system.system)
#main_entry.add_command(interactive.interactive)
