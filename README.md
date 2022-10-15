# flarequench

<a href="https://www.java.com"><img alt="lang" src="https://img.shields.io/badge/Lang-Java-blue.svg"></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img alt="license" src="https://img.shields.io/badge/License-Apache%202.0-red.svg"></a>

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

## Installation

### Compilation

1. Install and configure [Gradle](https://gradle.org/).

2. Download this repository.

   ```bash
   git clone https://github.com/aress31/flarequench
   cd .\flarequench\
   ```

3. Create the standalone `jar`:

   ```bash
   gradle build shadowJar
   ```

### Loading the Extension Into the `Burp Suite`

In `Burp Suite`, under the `Extender/Options` tab, click on the `Add` button and load the `fatJar` located in the `.\build\libs` folder.

## Roadmap

- [ ] Improve the reliablity.
- [x] Optimise the source code.

## Sponsor 💖

If you want to support this project and appreciate the time invested in developping, maintening and extending it; consider donating toward my next cup of coffee. ☕

It is easy, all you got to do is press the `Sponsor` button at the top of this page or alternatively [click this link](https://github.com/sponsors/aress31). 💸

## Reporting Issues

Found a bug? I would love to squash it! 🐛

Please report all issues on the GitHub [issues tracker](https://github.com/aress31/flarequench/issues).

## Contributing

You would like to contribute to better this project? 🤩

Please submit all `PRs` on the GitHub [pull requests tracker](https://github.com/aress31/flarequench/pulls).

## License

See [LICENSE](LICENSE).
