#!/usr/bin/env python2

import signal
import time
import logging
import random
import sys
import os

from network import networkmanager
import utils
from . import honggcomm
from twitterinterface import TwitterInterface
from target.servermanager import ServerManager
from common.crashdata import CrashData
from honggcorpusmanager import HonggCorpusManager
from mutator.mutatorinterface import MutatorInterface
from target import targetutils


def signal_handler(signal, frame):
    # TODO fixme make object so i can kill server
    #stopServer()
    sys.exit(0)


class HonggSlave(object):
    """
    The child thread of the HonggMode fuzzer.

    Implements the actual fuzzing logic, whereas the HonggMode
    class only starts this class as a dedicated thread.
    """

    def __init__(self, config, threadId, queue, initialSeed):
        self.config = config
        self.queue = queue
        self.threadId = threadId
        self.initialSeed = initialSeed
        self.iterStats = {
            "lastUpdate": 0,
            "iterCount": 0,
            "corpusCount": 0,
            "crashCount": 0,
            "hangCount": 0,
            "startTime": time.time(),
        }
        self.fuzzerPid = None
        self.tweeter = None

        if self.config['tweetcrash']:
            self.twitterInterface = TwitterInterface(self.config)
            self.twitterInterface.load()


    def doActualFuzz(self):
        """
        Child thread of fuzzer - does teh actual fuzzing.

        Sends results/stats via queue to the parent.
        Will start the target via honggfuzz, connect to the honggfuzz socket,
        and according to the honggfuzz commands from the socket, send
        the fuzzed messages to the target binary.

        New fuzzed data will be generated via HonggCorpusData, where
        the initial data from the corpus is managed by HonggCorpusManager.
        """
        if self.config['use_netnamespace']:
            targetutils.startInNamespace(self.realDoActualFuzz, self.threadId)
        else:
            self.realDoActualFuzz()


    def realDoActualFuzz(self):
        #logging.basicConfig(level=logging.DEBUG)
        if "debug" in self.config and self.config["debug"]:
            self.config["processes"] = 1

        if "DebugWithFile" in self.config and self.config["DebugWithFile"]:
            utils.setupSlaveLoggingWithFile(self.threadId)

        if 'use_netnamespace' in self.config and self.config['use_netnamespace']:
            targetPort = self.config["target_port"]
	   

        else:
            targetPort = self.config["target_port"] + self.threadId
        self.targetPort = targetPort

        logging.info("Setup fuzzing..")
        random.seed(self.initialSeed)
        signal.signal(signal.SIGINT, signal_handler)

        mutatorInterface = MutatorInterface(self.config, self.threadId)

        self.networkManager = networkmanager.NetworkManager(self.config, targetPort)
        self.corpusManager = HonggCorpusManager(self.config)
        self.corpusManager.loadCorpusFiles()
        if self.corpusManager.getCorpusCount() == 0:
            logging.error("No corpus input data found in: " + self.config['input_dir'])
            return
        # watch for new files / corpus
        self.corpusManager.startWatch()

        # start honggfuzz with target binary
        honggfuzzArgs = self._prepareHonggfuzzArgs()
        serverManager = ServerManager(
            self.config,
            self.threadId,
            targetPort,
            honggfuzzArgs,
            True
        )
        serverManager.start()

        # connect to honggfuzz
        honggComm = honggcomm.HonggComm()
	logging.info(honggcomm)
	#logging.info("started Honggfuzz" + str(serverManager.process.pid))
        if honggComm.openSocket(serverManager.process.pid) is not None:
            print (" connected to honggfuzz!")
            logging.info("Honggfuzz connection successful")
        else:
            logging.error("Could not connect to honggfuzz socket.")
            return

        # test connection first
        if not self.networkManager.debugServerConnection():
            logging.error("Bootstrap: Could not connect to server.")
            return

        # warmup
        # Send all initial corpus once and ignore new BB commands so we
        # dont add it again.
        # Note that at the end, there may be still commands in the socket
        # queue which we need to ignore on the fuzzing loop.
        initialCorpusIter = iter(self.corpusManager)
        print("Performing warmup. This can take some time.")
        while True:
            logging.debug("A warmup loop...")
            try:
                # this generates errors because multiple processes
                # try to write to stdout
                # sys.stdout.write('.')
                # sys.stdout.flush()
                initialCorpusData = initialCorpusIter.next()
            except StopIteration:
                break

            honggData = honggComm.readSocket()
            if honggData == "Fuzz":
                logging.debug("  Warmup Fuzz: Sending: " + str(initialCorpusData.filename))
                self._connectAndSendData(initialCorpusData)
                honggComm.writeSocket("okay")

            else:
                # We dont really care what the fuzzer sends us
                # BUT it should be always "New!"
                # It should never be "Cras"
                if honggData == "New!":
                    logging.debug("  Warmup: Honggfuzz answered correctly, received: " + honggData)
                else:
                    logging.warn("  Warumup: Honggfuzz answered wrong, it should be New! but is: " + honggData)

        # the actual fuzzing
        logging.debug("Warmup finished.")
        logging.info("Performing fuzzing")
        honggCorpusData = None

        # Just assume target is alive, because of the warmup phase
        # this var is needed mainly to not create false-positives, e.g.
        # if the target is for some reason unstartable, it would be detected
        # as crash
        haveCheckedTargetIsAlive = True

        while True:
            logging.debug("A fuzzing loop...")
            self._uploadStats()
            self.corpusManager.checkForNewFiles()
            honggData = None

            try:
                honggData = honggComm.readSocket()
            except Exception as e:
                logging.error("Could not read from honggfuzz socket: " + str(e))
                logging.error("Honggfuzz server crashed? Killed?")
                return

            # honggfuzz says: Send fuzz data via network
            if honggData == "Fuzz":
                couldSend = False

                # are we really sure that the target is alive? If not, check
                if not haveCheckedTargetIsAlive:
                    if not self.networkManager.waitForServerReadyness():
                        logging.error("Wanted to fuzz, but targets seems down. Force honggfuzz to restart it.")
                        try:
                            honggComm.writeSocket("bad!")
                        except Exception as e:
                            logging.error("Honggfuzz server crashed? Killed?")
                            return
                        self.iterStats["hangCount"] += 1
                    else:
                        haveCheckedTargetIsAlive = True

                # check first if we have new corpus from other threads
                # if yes: send it. We'll ignore New!/Cras msgs by setting:
                #   honggCorpusData = None
                if self.corpusManager.hasNewExternalCorpus():
                    honggCorpusData = None  # ignore results
                    corpus = self.corpusManager.getNewExternalCorpus()
                    corpus.processed = True
                    couldSend = self._connectAndSendData(corpus)

                # just randomly select a corpus, fuzz it, send it
                # honggfuzz will tell us what to do next
                else:
                    self.iterStats["iterCount"] += 1

                    corpus = self.corpusManager.getRandomCorpus()
                    honggCorpusData = mutatorInterface.fuzz(corpus)
                    couldSend = self._connectAndSendData(honggCorpusData)

                if couldSend:
                    # Notify honggfuzz that we are finished sending the fuzzed data
                    try:
                        honggComm.writeSocket("okay")
                    except Exception as e:
                        logging.error("Honggfuzz server crashed? Killed?")
                        return

                    # the correct way is to send SIGIO signal to honggfuzz
                    # https://github.com/google/honggfuzz/issues/200
                    os.kill(serverManager.process.pid, signal.SIGIO)
                else:
                    # target seems to be down. Have honggfuzz restart it
                    # and hope for the best, but check after restart if it
                    # is really up
                    logging.warn(str(self.threadId) + ": Server appears to be down, force restart at iteration " + str(self.iterStats['iterCount'])  )
                    self.iterStats["hangCount"] += 1
                    try:
                        honggComm.writeSocket("bad!")
                    except Exception as e:
                        logging.error("Honggfuzz server crashed? Killed?")
                        return

                    if self.config['hangsAreCrashes']:
                        self._handleCrash(honggCorpusData, 'hang')
                        self.iterStats["crashCount"] += 1

                    haveCheckedTargetIsAlive = False

            # honggfuzz says: new basic-block found
            #   (from the data we sent before)
            elif honggData == "New!":
                # Warmup may result in a stray message, ignore here
                # If new-corpus-from-other-thread: Ignore here
                if honggCorpusData is not None:
                    logging.info( "--[ Adding file to corpus...")
                    self.corpusManager.addNewCorpusData(honggCorpusData)
                    honggCorpusData.getParentCorpus().statsAddNew()

                    self.iterStats["corpusCount"] += 1

            # honggfuzz says: target crashed (yay!)
            elif honggData == "Cras":
                # Warmup may result in a stray message, ignore here
                # If new-corpus-from-other-thread: Ignore here
                if honggCorpusData is not None:
                    logging.info( "--[ Adding crash...")
                    self._handleCrash(honggCorpusData, 'honggcomm')
                    self.iterStats["crashCount"] += 1

                # target was down and needs to be restarted by honggfuzz.
                # check if it was successfully restarted!
                haveCheckedTargetIsAlive = False

            elif honggData == "":
                logging.info("Hongfuzz quit, exiting too\n")
                break
            else:
                # This should not happen
                logging.error( "--[ Unknown Honggfuzz msg: " + str(honggData))

            # periodically restart server
            if self.iterStats['iterCount'] > 0 and self.iterStats['iterCount'] % self.config['restart_server_every'] == 0:
                logging.info("restart server periodically at iteration " + str(self.iterStats['iterCount']))
                try:
                    honggComm.writeSocket("bad!")
                except Exception as e:
                    logging.error("Honggfuzz server crashed? Killed?")
                    return

                haveCheckedTargetIsAlive = False

            if self.iterStats['iterCount'] > 0 and self.iterStats['iterCount'] % 300 == 0:
                self.networkManager.tuneTimeouts( self.corpusManager.getMaxLatency() )


    def _connectAndSendData(self, corpusData):
        return self.networkManager.sendAllData(corpusData)


    @staticmethod
    def createHonggSlaveMasterData(
            threadId,
            iterCount,
            corpusCount,
            corpusCountOverall,
            crashCount,
            hangCount,
            fuzzPerSec,
            maxLatency,
            timeoutCount):
        d = {}
        d['threadId'] = threadId
        d['iterCount'] = iterCount
        d['corpusCount'] = corpusCount
        d['corpusCountOverall'] = corpusCountOverall
        d['crashCount'] = crashCount
        d['hangCount'] = hangCount
        d['fuzzPerSec'] = fuzzPerSec
        d['maxLatency'] = maxLatency
        d['timeoutCount'] = timeoutCount
        return d


    def _uploadStats(self):
        """Send fuzzing statistics to parent."""
        currTime = time.time()
        updateInterval = 3

        if currTime > self.iterStats["lastUpdate"] + updateInterval:
            # only show detailed stats if we dont have many processes
            if self.config['processes'] <= 2:
                self.corpusManager.printStats()
            fuzzPerSec = float(self.iterStats["iterCount"]) / float(currTime - self.iterStats["startTime"])

            # send fuzzing information to parent process
            d = HonggSlave.createHonggSlaveMasterData(
                self.threadId,
                self.iterStats["iterCount"],
                self.iterStats["corpusCount"],
                self.corpusManager.getCorpusCount(),
                self.iterStats["crashCount"],
                self.iterStats["hangCount"],
                fuzzPerSec,
                self.corpusManager.getMaxLatency(),
                self.corpusManager.getTimeoutCount())
            self.queue.put( d )
            self.iterStats["lastUpdate"] = currTime

            if "fuzzer_nofork" in self.config and self.config["fuzzer_nofork"]:
                d = (self.threadId,
                     self.iterStats["iterCount"],
                     self.iterStats["corpusCount"],
                     self.corpusManager.getCorpusCount(),
                     self.iterStats["crashCount"],
                     self.iterStats["hangCount"],
                     fuzzPerSec,
                     self.corpusManager.getMaxLatency(),
                     self.corpusManager.getTimeoutCount())

                print(" %5d: %11d  %9d  %13d  %7d  %4.2f" % d)



    def _prepareHonggfuzzArgs(self):
        """Add all necessary honggfuzz arguments."""
        logging.debug( "Starting server/honggfuzz")
        cmdArr = [ ]

        cmdArr.append(self.config["honggpath"])  # we start honggfuzz
        cmdArr.append('--keep_output')  # keep children output (in log)
        cmdArr.append('--sanitizers')
	cmdArr.append('--sancov')  # Sanitizer coverage feedback, default in honggfuzz 1.2
        cmdArr.append('--threads')  # only one thread
        cmdArr.append('1')
        cmdArr.append('--stdin_input')
        cmdArr.append('--socket_fuzzer')

        # disable LeakAnalyzer because it makes honggfuzz crash
        # https://github.com/dobin/ffw/issues/20
        cmdArr.append('--san_opts')
        cmdArr.append('detect_leaks=0')

        if self.config["debug"]:
            # enable debug mode with log to file
            cmdArr.append("-d")
            cmdArr.append('-l')
            cmdArr.append('honggfuzz.log')

        # only append honggmode specific option if available
        if self.config["honggmode_option"]:
            cmdArr.append(self.config["honggmode_option"])

        # add target to start
        cmdArr.append("--")

        return cmdArr


    def _handleCrash(self, honggCorpusData, fuzzerPosition):
        # check if core exists
        if self.config['handle_corefiles']:
            n = 0
            while n < 4:
                corepath = os.path.join(self.config['target_dir'], 'core')
                if os.path.isfile(corepath):
                    break

                time.sleep(0.1)
                n += 1

        print('Found crash!')
        crashData = CrashData(self.config, honggCorpusData, fuzzerPosition)
        crashData.writeToFile()

        if self.config['tweetcrash']:
            msg = "Found crash in " + self.config['name']
            msg += ""
            self.twitterInterface.tweet(msg)
