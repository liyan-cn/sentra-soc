"""Audit every installed third-party distribution, excluding only this local app."""
from importlib.metadata import distributions
from pathlib import Path
import re
import subprocess
import sys


def main():
    packages={}
    for distribution in distributions():
        name=distribution.metadata['Name']
        if not name or not distribution.version:raise ValueError('incomplete distribution metadata')
        canonical=re.sub(r'[-_.]+','-',name).lower()
        if canonical=='monitor3':continue  # Local source is reviewed by Bandit, not published to PyPI.
        if canonical in packages and packages[canonical]!=distribution.version:
            raise ValueError('conflicting installed distribution: '+canonical)
        packages[canonical]=distribution.version
    path=Path('dependency-audit-installed.txt')
    path.write_text(''.join(f'{name}=={version}\n' for name,version in sorted(packages.items())),encoding='utf8')
    print(f'Auditing {len(packages)} exact installed third-party versions.',flush=True)
    subprocess.run([sys.executable,'-m','pip_audit','--strict','--no-deps','--disable-pip','-r',str(path)],check=True)


if __name__=='__main__':main()
