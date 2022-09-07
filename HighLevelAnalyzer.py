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

# splits telegramparts with dividers RS, GS, US
class TelegramSplitter:
    def __init__(self, data):
        self.data = data

    def get_group(self, groupindex = 0):
        groups = self.data.split(GS)
        if groupindex >= len(groups):
            return ""
        return groups[groupindex]
        
    def get_rows(self, groupindex = 0):
        return self.get_group(groupindex).split(RS)

    def get_row(self, rowindex = 0, groupindex = 0):
        rows = self.get_rows(groupindex)
        if rowindex >= len(rows):
            return ""
        return rows[rowindex]

    # return all units as array
    def get_units(self, rowindex = 0, groupindex = 0):
        return self.get_row(rowindex, groupindex).split(US)
            
    def get_unit(self, unitindex = 0, rowindex = 0, groupindex = 0):
        units = self.get_units(rowindex, groupindex)
        if unitindex >= len(units):
            return ""
        return units[unitindex]


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
                params = TelegramSplitter(params)
                unit0 = params.get_unit(0)
                eok = unit0[0]
                temp = ""
                if eok == '0':
                    temp = f'OK "{unit0[1]}"'
                else:
                    temp = f'ZOK "{unit0[1:]}"'

                unit1 = params.get_unit(1)
                ob = unit1[0]
                temp += f', OB "{ob}"'

                sb = unit1[1:]
                if len(sb) > 0:
                    temp += f', SB "{sb}"'

                fh = params.get_unit(2)
                if fh != "":
                    temp += f', FH "{fh}"'

                return f'Job req namelist EOK "{eok}", ' + temp

            elif dk == DK_IDENTIFICATOIN:
                return 'Job req ID'

            elif dk == DK_VAR_READ:
                za = params[0]
                tmp = "?"
                if za == '0':
                    params = TelegramSplitter(params[1:])
                    tmp = ', '.join(params.get_rows())
                elif za == '1':
                    tmp = params[1:]
                return f'Job req read var ZA {za}, {tmp}'

            elif dk == DK_VAR_WRITE:
                za = params[0]
                tmp = '?'
                if za == '0':
                    params = TelegramSplitter(params[1:])
                    tmp = 'names ' + ', '.join(params.get_rows())
                    tmp += ', values ' + ', '.join(params.get_units(0, 1))
                elif za == '1':
                    tmp = params[1:]
                return f'Job req write var ZA {za}, {tmp}'

        elif tk == TK_JOB_REP:
            an = data[1] # Auftragsnummer
            dk = data[2] + data[3] # Dienstkennungszeichen 1 & 2
            params = data[4:]

            if dk == DK_STATUS:
                return f'Job rep status "{params}"'

            elif dk == DK_NAMELIST:
                params = TelegramSplitter(params)
                varlist = ', '.join(params.get_units(0))
                return f'Job rep namelist: {varlist}'
                
            elif dk == DK_IDENTIFICATOIN:
                params = TelegramSplitter(params)
                return f'Job rep ID HN "{params.get_unit(0)}", MN "{params.get_unit(1)}", version "{params.get_unit(2)}"'

            elif dk == DK_VAR_READ:
                params = TelegramSplitter(params)
                list = ', '.join(params.get_units())
                return f'Job rep read var "{list}"'

            elif dk == DK_VAR_WRITE:
                return f'Job rep write var "{params}"'

        elif tk == TK_EVENT:
            dk3 = data[1]
            if dk3 == '0':
                return f'Event report "{data[2:]}"'
            if dk3 == '1':
                return f'Event status "{data[2:]}"'

        elif tk == TK_CONNECT_REQ:
            params = TelegramSplitter(data[1:])
            called = params.get_unit(0)
            caller = params.get_unit(1)
            unit2 = params.get_unit(2)
            odrv = ord(unit2[0]) - 0x40
            odgv = ord(unit2[1]) - 0x40
            version = unit2[2:]
            return f'Connect req, VN "{vn}", "{caller}" -> "{called}", ODRV {odrv}, ODGV {odgv}, version "{version}"'

        elif tk == TK_CONNECT_REP:
            odrf = ord(data[1]) - 0x40
            odgf = ord(data[2]) - 0x40
            version = data[3:]
            return f'Connect rep, VN "{vn}", ODRF {odrf}, ODGF {odgf}, version "{version}"'

        elif tk == TK_CONNECT_ERR:
            return 'Connect error'

        elif tk == TK_CONNECTION_ABORT:
            return 'Connect abort'

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
            'format': '{{{data.Info}}}'
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
