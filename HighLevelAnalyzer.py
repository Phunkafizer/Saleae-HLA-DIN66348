# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import json

STX = chr(0x02)
ETX = chr(0x03)
EOT = chr(0x04)
ENQ = chr(0x05)
DLE = chr(0x10)
DC2 = chr(0x12)
DC4 = chr(0x14)
NAK = chr(0x15)
FS = chr(0x1C)
GS = chr(0x1D)
RS = chr(0x1E)
US = chr(0x1F)

CTRL_CHR = {
    DC4: "<DC4>",
    DC2: "<DC2>",
    FS: "<FS>",
    GS: "<GS>",
    RS: "<RS>",
    US: "<US>"
}

STATE_IDLE = 0
STATE_DATABLOCK = 1
STATE_BCC = 2
STATE_DLE = 3

ROLE_MASTER = 0
ROLE_SLAVE = 1

TK_JOB_REQ = '0'        # Auftragsbearbeitung Anforderungstelegram
TK_JOB_REP = '1'        # Auftragsbearbeitung Antwortstelegram
TK_EVENT = '3'          # Ereignis Meldungstelegram
TK_CONNECT_REQ  = '8'   # Verbindungsaufbau Anforderungstelegram
TK_CONNECT_REP  = '9'   # Verbindungsaufbau Antwortstelegram
TK_CONNECT_ERR = 'A'    # Verbinidungsaufbau Fehlertelegramm
TK_DISCONNECT_REQ = 'B' # Verbinidungsabbau Anforderungstelegram
TK_DISCONNECT_REP = 'C' # Verbinidungsabbau Antwortstelegram
TK_DISCONNECT_ERR = 'D' # Verbinidungsabbau Fehlertelegramm
TK_CONNECTION_ABORT = 'E' # Verbindungsabbruch Meldungstelegram

DK_STATUS = '00'        
DK_NAMELIST = '01'
DK_IDENTIFICATOIN = '02'
DK_VAR_READ = '04'
DK_VAR_WRITE = '05'

# DIN Protocol parser for application data
class DataBlock:
    def __init__(self, payload, bcc):
        self.payload = payload
        self.bccok = False

        self.vn = ''
        dc4pos = payload.find(DC4)
        if (dc4pos >= 0):
            self.vn = payload[dc4pos + 1] + payload[dc4pos + 2]

    def parse(self, vn, data):
        tk = data[0] #Telegrammtypkennung

        if tk == TK_JOB_REQ:
            an = data[1] # Auftragsnummer
            dk = data[2] + data[3] # Dienstkennungszeichen 1 & 2
            params = data[4:]
            if dk == DK_STATUS:
                return f'Job req status {params}'
            if dk == DK_NAMELIST:
                return f'Job req namelist {params}'
            elif dk == DK_IDENTIFICATOIN:
                return 'Job req ID'
            elif dk == DK_VAR_READ:
                return f'Job req read var {params}'
            elif dk == DK_VAR_WRITE:
                return f'Job req write var {params}'

        elif tk == TK_JOB_REP:
            an = data[1] # Auftragsnummer
            dk = data[2] + data[3] # Dienstkennungszeichen 1 & 2
            params = data[4:]
            if dk == DK_STATUS:
                return f'Job rep status {params}'
            elif dk == DK_NAMELIST:
                return f'Job rep namelist {params}'
            elif dk == DK_IDENTIFICATOIN:
                return f'Job rep ID {data[4:]}'
            elif dk == DK_VAR_READ:
                return f'Job rep read var {params}'
            elif dk == DK_VAR_WRITE:
                return f'Job rep write var {params}'

        elif tk == TK_EVENT:
            dk3 = data[1]
            if dk3 == '0':
                return f'Event report {data[2:]}'
            if dk3 == '1':
                return f'Event status {data[2:]}'

        elif tk == TK_CONNECT_REQ:
            sp = data[1:].split(US)
            called = sp[0]
            caller = sp[1]
            odrv = ord(sp[2][0]) - 0x40
            odgv = ord(sp[2][1]) - 0x40
            version = sp[2][2:]
            return f'Connect req VN {vn} {caller} - {called} version {version}'

        elif tk == TK_CONNECT_REP:
            odrf = ord(data[1]) - 0x40
            odgf = ord(data[2]) - 0x40
            version = data[3:]
            return f'Connect rep VN {vn} version {version}'

        elif tk == TK_CONNECT_ERR:
            return 'Connect error'

        elif tk == TK_DISCONNECT_REQ:
            return 'Disconnect req'

        elif tk == TK_DISCONNECT_REP:
            return 'Disconnect rep'

        elif tk == TK_DISCONNECT_ERR:
            return 'Disconnect error'

        return data

    def __str__(self):
        dc2pos = self.payload.find(DC2)
        if dc2pos >= 0:
            return self.parse(self.vn, self.payload[dc2pos+1:-1])
        
        s = ""
        for c in self.payload:
            if c >= 0x20:
                s += chr(c)
            elif c in CTRL_CHR:
                s += CTRL_CHR[c]
            else:
                s += '<?>' + hex(c)

        return s

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'Data': {
            'format': '{{data.Info}}'
        },
        'Ctrl': {
            'format': '{{data.Info}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''
        
        self.last_char = ''
        self.last_char_start_time = None
        self.stx_start_time = None
        self.state = STATE_IDLE
        self.databuf = ''
        self.address = ''

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        '''

        result = None
        
        c = chr(frame.data['data'][0])
        
        if self.state == STATE_BCC: #receive BCC
            print(self.databuf)
            datablock = DataBlock(self.databuf, c)
            self.state = STATE_IDLE
            result = AnalyzerFrame('Data', self.stx_start_time, frame.end_time, {'Info': str(datablock), 'Adr': str(self.address), 'VN': datablock.vn})
            
        elif self.state == STATE_DLE: #receive DLE byte
            result = AnalyzerFrame('Ctrl', self.last_char_start_time, frame.end_time, {'Info': 'DLE ' + c})
            self.state = STATE_IDLE
            
        else:
            if c == STX:
                self.state = STATE_DATABLOCK
                self.databuf = ""
                self.stx_start_time = frame.start_time
            elif c == EOT:
                self.state = STATE_IDLE
                result = AnalyzerFrame('Ctrl', frame.start_time, frame.end_time, {'Info': 'EOT', 'Adr': str(self.address)})
                
            elif c == ETX:
                if self.state == STATE_DATABLOCK:
                    self.state = STATE_BCC
            elif c == ENQ:
                self.address = ord(self.last_char) & 0x1F
                dir = 'TX' if (ord(self.last_char) & 0x20) == 0 else 'RX' 
                info = dir + ' ENQ adr ' + str(self.address)
                result = AnalyzerFrame('Ctrl', self.last_char_start_time, frame.end_time, {'Info': info, 'Adr': str(self.address)})
                
            elif c == DLE:
                self.state = STATE_DLE

            elif c == NAK:
                result = AnalyzerFrame('Ctrl', self.last_char_start_time, frame.end_time, {'Info': 'NAK'})

        if (self.state == STATE_DATABLOCK) and (c != STX):
            self.databuf += c
        
        
        self.last_char = c
        self.last_char_start_time = frame.start_time

        if result:
            return result
