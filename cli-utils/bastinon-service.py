#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

# This file is part of Spammer Block library and tool.
# Spamer Block is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (c) Jari Turkia

import os
import sys
from systemd_watchdog import watchdog
import asyncio
import asyncio_glib
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GObject  # PyGObject
from typing import Optional, Tuple
from periodic import Periodic  # asyncio-periodic
import signal
from bastinon.rules import ServiceReader
from bastinon import FirewallBase, Iptables, dbus
import argparse
import logging

log = logging.getLogger(__name__)
wd: watchdog = None

DEFAULT_SYSTEMD_WATCHDOG_TIME = 5

BUS_SYSTEM = "system"
BUS_SESSION = "session"


def _setup_logger(log_level_in: str) -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)

    if log_level_in.upper() not in logging._nameToLevel:
        raise ValueError("Unkown logging level '{}'!".format(log_level_in))
    log_level = logging._nameToLevel[log_level_in.upper()]
    log.setLevel(log_level)

    lib_log = logging.getLogger('firewall_updater')
    lib_log.setLevel(log_level)
    lib_log.addHandler(console_handler)


async def _systemd_watchdog_keepalive() -> None:
    # Systemd notifications:
    # https://www.freedesktop.org/software/systemd/man/sd_notify.html
    wd.notify()


async def _systemd_mock_watchdog() -> None:
    # Systemd notifications:
    # https://www.freedesktop.org/software/systemd/man/sd_notify.html
    log.debug("(mock) Systemd watchdog tick/tock")


def daemon(use_system_bus: bool, firewall: FirewallBase, firewall_rules_path: str, watchdog_time: int) -> None:
    dbus_loop = DBusGMainLoop(set_as_default=True)
    asyncio.set_event_loop_policy(asyncio_glib.GLibEventLoopPolicy())
    asyncio_loop = asyncio.get_event_loop()

    # Publish the interactive service into D-Bus
    dbus.FirewallUpdaterService(
        use_system_bus,
        dbus_loop,
        firewall,
        firewall_rules_path
    )

    # Go loop until forever.
    log.debug("Going for asyncio event loop using GLib main loop. PID: {}".format(os.getpid()))
    canceled = False

    def _cancellation_event_factory() -> asyncio.Event:
        # Create an event that gets set when the program is interrupted.
        # Note: Abusing Event-class a bit
        # Source code: https://github.com/python/cpython/blob/af6b4068859a5d0c8afd696f3c0c0155660211a4/Lib/multiprocessing/synchronize.py#L321
        cancellation_event = asyncio.Event()
        cancellation_event.signal = None

        def _cancel_handler(num: int) -> None:
            name = signal.Signals(num).name
            log.warning(
                'Firewall Updater service received signal: {} ({}). Setting cancellation event.'.format(name, num))
            cancellation_event.set()
            cancellation_event.signal = num

        for signal_value in {signal.SIGINT, signal.SIGTERM}:
            # Note: signal_value is doubled. 2nd is the argument.
            # When signal_value is captured, a call into _cancel_handler(signal_value) will be made.
            asyncio_loop.add_signal_handler(signal_value, _cancel_handler, signal_value)

        return cancellation_event

    async def _daemon_main(cancel_event: asyncio.Event):
        # Systemd watchdog?
        if wd.is_enabled:
            # Sets a function to be called at regular intervals with the default priority, G_PRIORITY_DEFAULT.
            # https://docs.gtk.org/glib/func.timeout_add_seconds.html
            log.debug("Systemd Watchdog enabled")
            wd.ready()
            periodic_job = Periodic(watchdog_time, _systemd_watchdog_keepalive)
        else:
            log.info("Systemd Watchdog not enabled")
            if False:
                periodic_job = Periodic(watchdog_time, _systemd_mock_watchdog)
            else:
                periodic_job = None

        if periodic_job:
            await periodic_job.start()
        cancellation_task = asyncio_loop.create_task(cancel_event.wait())
        # Ok, in this wait() there is only single task. It's just there _could_ be more.
        while not cancel_event.is_set():
            done, pending = await asyncio.wait(
                [cancellation_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            for done_task in done:
                if done_task == cancellation_task:
                    # Now that we know this completed task is wait for cancellation event,
                    # go read the caught signal number from the event itself.
                    # See, Abusing Event-class a bit, above.
                    sig_num = cancel_event.signal
                    sig_name = signal.Signals(sig_num).name
                    log.debug("Caught {}. Will exit loop.".format(sig_name))

        log.debug("Main loop done!")

    # Append asyncio-stuff to be run
    cancel_event = _cancellation_event_factory()

    # Go for Glib event loop, runs also asyncio
    log.debug("Enter loop")
    asyncio_loop.run_until_complete(_daemon_main(cancel_event))
    log.debug("Exit loop")
    log.info("Done monitoring for firewall changes.")


class NegateAction(argparse.Action):
    """
    Argparse helper
    """
    def __call__(self, parser, ns, values, option):
        setattr(ns, self.dest, option[2:5] != 'non')


def main() -> None:
    parser = argparse.ArgumentParser(description='Firewall Updates daemon')
    parser.add_argument('bus_type', metavar='BUS-TYPE-TO-USE', choices=[BUS_SYSTEM, BUS_SESSION],
                        help="D-bus type to use. Choices: {}".format(', '.join([BUS_SYSTEM, BUS_SESSION])))
    parser.add_argument("rule_path", metavar="RULE-PATH",
                        help="User's firewall rules base directory")
    parser.add_argument('--watchdog-time', type=int,
                        default=DEFAULT_SYSTEMD_WATCHDOG_TIME,
                        help="How often systemd watchdog is notified. "
                             "Default: {} seconds".format(DEFAULT_SYSTEMD_WATCHDOG_TIME))
    parser.add_argument('--stateful', '--non-stateful', dest='stateful',
                        action=NegateAction, nargs=0,
                        help="Do not use stateful TCP firewall. Default: use stateful")
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level. Python default is: WARNING')
    args = parser.parse_args()

    _setup_logger(args.log_level)

    if args.bus_type == BUS_SYSTEM:
        using_system_bus = True
    elif args.bus_type == BUS_SESSION:
        using_system_bus = False
    else:
        raise ValueError("Internal: Which bus?")

    # Watchdog
    global wd
    wd = watchdog()

    reader = ServiceReader(args.rule_path)
    iptables_firewall = Iptables(reader.read_all(), "Friends-Firewall-INPUT", args.stateful)

    log.info('Starting up ...')
    daemon(
        using_system_bus,
        iptables_firewall,
        args.rule_path,
        args.watchdog_time
    )


if __name__ == "__main__":
    main()
