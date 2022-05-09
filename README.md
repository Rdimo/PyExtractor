<h1 align="center">
  PyExtractor 🐍
</h1>

<p align="center"> 
  <kbd>
<img src="https://raw.githubusercontent.com/Rdimo/images/master/PyExtractor/snake.png"></img>
  </kbd>
</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/Rdimo/PyExtractor?style=flat-square" </a>
  <img src="https://img.shields.io/github/last-commit/Rdimo/PyExtractor?style=flat-square" </a>
  <img src="https://sonarcloud.io/api/project_badges/measure?project=PyExtractor&metric=ncloc" </a>
  <img src="https://img.shields.io/github/stars/Rdimo/PyExtractor?color=9acd32&label=Stars&style=flat-square" </a>
  <img src="https://img.shields.io/github/forks/Rdimo/PyExtractor?color=9acd32&label=Forks&style=flat-square" </a>
</p>

<h4 align="center">
  <a href="https://cheataway.com">🌌・Discord</a>
  <a href="https://github.com/Rdimo/PyExtractor#getting-started-with-PyExtractor">🐍・Getting started</a>
  <a href="https://github.com/Rdimo/PyExtractor#changelog">📜・ChangeLog</a>
</h4>

<h2 align="center">
  PyExtractor was made by

Love ❌ code ✅

</h2>

---

## :fire: Features

✔ Fully Decompiles executables compiled with `pyinstaller` or `py2exe` \
✔ From .exe --> .py \
✔ Configurable with json config \
✔ Exe must **NOT** be compiled with a python compiler in order for PyExtractor to check it\
✔ Checks file(s) for suspicious words, discord webhooks, discord invites, pastebins, urls, ips etc..\
✔ Check if the file hash is a known malware/virus \
✔ Fetches general info and sections about the binary

---

## 🐍・Getting started with PyExtractor!

If you don't [Git](https://git-scm.com) to start off!

```sh-session
git@2.17.1 or higher
```

##### 1. From your command line, clone and configure PyExtractor:

```bash
# Clone this repository
$ git clone https://github.com/Rdimo/PyExtractor.git
```

or

```bash
# Downloading as zip
$ press big green code button
$ press download ZIP
```

[forking](https://github.com/Rdimo/PyExtractor/fork) this repo is also a viable way

##### 2. after you've extracted the zip file:

Make to open [config.json](https://github.com/Rdimo/PyExtractor/blob/master/config.json) and change the settings to your preferences ⇣⇣⇣

```json
{
  "detailed_logs": false, //Console logs the binary sections and general info
  "error_stack_logs": true, //Send out full error message
  "time_stamp_logging": true, //Timestamp in the logs.log file

  "analyse_file": true, //Checks the file(s) for suspicious words, discord webhooks, discord invites, pastebins, urls, ips etc..
  "malware_recognize": true //Check if the file hash is a known malware/virus
}
```

## 🎉・ideas/todo?

- Check for more things
- Better malware recognizer
- Fix
- More config options

## 💭・ChangeLog

```diff
v0.0.1 ⋮ 2022-05-09
+ Official release
```
