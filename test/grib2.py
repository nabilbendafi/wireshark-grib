#!/usr/bin/env python
# Routines for GRIB dissection
#
# Copyright (c) 2016 Nabil BENDAFI
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import unittest
from os.path import join, dirname
import pyshark


class WiresharkGRIB2TestCase(unittest.TestCase):

    def setUp(self):
        filename = join(dirname(__file__), 'data', 'GRIB2.pcap')
        self.packet = pyshark.FileCapture(filename)

    def test_(self):
       """Test packet properties."""
       self.assertEqual(self.packet[3].highest_layer, 'GRIB') 
       self.assertEqual(self.packet[3].tcp.dstport, '9999')

if __name__ == '__main__':
    # Rock'n'Roll
    unittest.main()
