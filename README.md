# Note

Deniable covert communications.

Like passing notes in class, but more secure.

"Dissidents in repressive regimes or victims of domestic abuse may have their phones occasionally confiscated and scanned, network traffic monitored, they may not be able to install a secure chat app at all, or may be punished for installing one, they may be identified and imprisoned if metadata or contacts show them connected or communicating with someone deemed undesirable at all. I'm not aware of any other system that the information security community recommends or even seeks to build to enable secure communication in these circumstances."

Expanded version of https://www.scriptjunkie.us/2021/09/covert-credit-calculation-communications/

Aspirational goals:
- Passive network monitoring or active network-controlling adversaries should not be able to decrypt message contents without the sender or recipient's keys.
- Passive network monitoring adversaries should not be able to determine whether a user is using the hidden messaging functionality on a site and active network adversaries should find that difficult.
- Unless screen capture/keystroke recording spyware is installed, a forensic analysis of a system should not be able to determine whether it was used to participate in secret messaging once the browser is closed and browser memory is reused for another purpose.

## Implementation notes

Servers facilitate peer-to-peer connections between clients over webrtc.

Changes in connections are broadcast immediately (new clients or servers joining or being disconnected).

Each node has an asymmetric keypair it announces. Chat participants additionally have a more secret keypair.

Each client sends a fixed size chunk of data at regular intervals encrypted to each system it is directly connected with.

This chunk may include instructions to forward inner wrapped encrypted messages to other nodes (which will be padded back to size for the next scheduled send).

Nodes can be instructed to act as forwards (if they receive a message for key X, wrap in encryption for key Y and forward to another node).

Setting a chain of forwards for ephemeral secret keys allows for rendezvous points to be used as destinations.

Each endpoint keep a list of server URL's, assigning each a (local) integer.
Each server keep a list of connected clients, assigning each a server-specific integer.
Endpoints are identified by a pair of numbers - the server int and client int.
Peer links are identified by a quad - server/client for the first side and server/client for the other side.
