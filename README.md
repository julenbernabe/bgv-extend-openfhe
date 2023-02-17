# Extending the BGV library in OpenFHE

## Previous steps

Before being able to use this repository, it is important to compile the OpenFHE library. To do so, follow the steps shown in these links:

- [Linux](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/linux.html)
- [Windows](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/windows.html)
- [MacOS](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/macos.html)

Once you have completed the installation steps, you can now use the code available in this repository.

## Installation of the repository

1. Download the repository.
2. Enter the build folder and open a terminal inside it.
3. Run `make`. This will create two executables: `bgv-compare` and `bgv-int-division`.
4. To run comparisons over BGV, run `./bgv-compare`. To run integer divisions, run `./bgv-int-division`.
