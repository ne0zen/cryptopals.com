My (WIP) solutions to the Matasano/Cryptopals Crypto Challenges.

More details at https://cryptopals.com/<br/>
Despite involvement in a couple CTFs and an interest in old ciphers, I'm not well-versed in modern crypto let alone in attacking it.  I'm hoping that changes after this journey.

# Execution
Most solutions can be executed by treating them as executables

```
cd /path/to/cloned/repo
./challengeX.py
```
Where `X` stands for the relevant challenge number.

# Testing
Haven't decided whether I'll go full bore on picking up [pytest](https://pytest.org/latest/) for this yet.
Though I'm intrigued by the promise of that framework.

For now, Tests can be run by

```
python3 -m doctest challengeX.py -v
```
Where `X` stands for the relevant challenge number.


# Implementation Notes

* There will be more code duplication here than would normally be in my production-level code.
* Its closer to what I'd call [Spike](https://en.wikipedia.org/wiki/Spike_(software_development)) code at an employer.
* Built & tested these on Python 3.5.1 should work on later versions
