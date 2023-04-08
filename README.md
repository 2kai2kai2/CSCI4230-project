# For Team Blackhat
## Running
1. Setup: run `pip install -r requirements.txt` to install dependencies
2. Run `server.py` to start the server
3. To start a client session, run `client.py`

## Implementation Notes
- The database resets whenever the server is restarted.

## Accounts
We have included a few accounts in the database. We did our best to make sure you can't access most of them without knowing server internals.

### Mallory Malificent
*This is you!*
|                 |                    |
| --------------- | ------------------ |
| Card Number     | `0000000000000000` |
| CVC             | `666`              |
| Expiration Date | `04/2025`          |
| PIN             | `6969`             |

### Charlie Collaborator
*If you steal from Charlie you're a bad friend. But maybe they'll let you intercept their messages for science.*
|                 |                    |
| --------------- | ------------------ |
| Card Number     | `0000000000000505` |
| CVC             | `111`              |
| Expiration Date | `05/2025`          |
| PIN             | `1111`             |

### Alice Allison
*Alice keeps her bank information very secret.*
|                 |                    |
| --------------- | ------------------ |
| Card Number     | (random)           |
| CVC             | (random)           |
| Expiration Date | `05/2025`          |
| PIN             | (random)           |

### Bobby McBobface
*Bobby is less good at keeping secrets than Alice.*
|                 |                    |
| --------------- | ------------------ |
| Card Number     | `0505050505050505` |
| CVC             | `123`              |
| Expiration Date | `06/2023`          |
| PIN             | (random)           |

### Victor Evilson
*Maybe you feel bad about stealing from Bobby. Victor is very evil so the only issue with stealing from him is that he might come find you.*
|                 |                    |
| --------------- | ------------------ |
| Card Number     | `4111111111111111` |
| CVC             | (random)           |
| Expiration Date | `09/2026`          |
| PIN             | (random)           |

### Billy Bazillionaire
*Billy has a lot of money. He probably wouldn't miss it if some disappeared, right?*
|                 |                    |
| --------------- | ------------------ |
| Card Number     | (random)           |
| CVC             | (random)           |
| Expiration Date | `12/2100`          |
| PIN             | (random)           |