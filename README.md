# DIN 66348 DIN measurement bus
Analyzes application- & datalinklayers. 
Data will be listed in data panel as 2 different datatypes:
## Ctrl
Control data, as addressing, flow control, DLE, EOT
## Data
Data frames contained between a pair of STX and ETX

# Analyzed frames in application layer
## Telegram types (TK)
* '0': Job request
* '1': Job reply
* '3': Event
* '8': Connect request
* '9': Connect reply
* 'A': Connect error
* 'B': Disconnect request
* 'C': Disconnect reply
* 'D': Disconnect error
* 'E': Connection abort

## Job types (DK)
* 0-0: Status
* 0-1: Namelist
* 0-2: Identification
* 0-4: Read variable
* 0-5: Write variable
# Used abbreviations in analyzer frames
|          |               |
|----------|:-------------:|
| ENQ | enquery |
| EOT | end of transmission |
| DLE | data link escape |
| req | request |
| rep | reply |
| VN | Verbindungsnummer |
| ODRV | Offene Dienste rufend vorgeschlagen |
| ODGV | Offene Dienste gerufen vorgeschlagen |
| ODRF | Offene Dienste rufend festgelegt |
| ODGF | Offene Dienste gerufen festgelegt |
| HN | Herstellername |
| MN | Modellname |
| EOK | Ergänzende Objektklasse |
| OK  | Objektklasse |
| ZOK | Zusätzliche Objektklasse |
| FH | Fortsetzung-hinter |
| ZA | Zugriffsart |

# Links
* https://de.wikipedia.org/wiki/DIN-Messbus
* http://www.measurement-bus.de/