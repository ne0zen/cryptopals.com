My (WIP) solutions to the Matasano/Cryptopals Crypto Challenges.

More details at https://cryptopals.com/
Despite involvement in a couple CTFs I'm not really extremely well versed in anything like modern Crypto.

h1. Execution
Most solutions can be executed by treating them as executables

```
cd /path/to/cloned/repo
./challengeX.py
```
Where `X` stands for the relevant challenge number.

h1. Testing
Haven't decided whether I'll go full bore on picking up [pytest](https://pytest.org/latest/) for this yet.
Though I'm intrigued by the promise of that framework.

For now, Tests can be run by

```
python3 -m doctest challengeX.py
```
Where `X` stands for the relevant challenge number.


h1. Implementation Notes

* There will be more code duplication here than would normally be in my production-level code.
* Its closer to what I'd call [Spike](https://en.wikipedia.org/wiki/Spike_(software_development)) code at an employer.
