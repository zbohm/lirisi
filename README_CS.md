# Jednoznačný kruhový podpis

Projekt `Lirisi` implementuje schéma kruhového podpisu podle návrhu v dokumentu [Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups](LSAGS-027.pdf), který v roce 2004 sepsali Joseph K. Liu, Victor K. Wei a Duncan S. Wong.

## Anonymita, jednoznačnost, rovnost

Schéma definuje postup, jak vytvořit a ověřit elektronický podpis, který splňuje tři základní požadavky: anonymitu, jednoznačnost a rovnost.
**Anonymita** znamená, že z podpisu nelze zjistit, kdo konkrétně ze skupiny podepisujích jej vytvořil.
**Jednoznačnost** znamená, že z podpisu lze vyčíst, jestli již existuje jiný podpis podepsaný stejným podepisujícím, a to i přesto, že samotný podepisující tím není vyzrazen.
**Rovnost** znamená, že nikdo ze skupiny podepisujících není v podpisu nadřazený. Na rozdíl od skupinového podpisu, kde existuje „správce skupiny“, který zná identitu podepisujícíh, v kruhovém podpisu si jsou všichni rovni.


Tyto vlastnosti umožňují použít podpis všude tam, kde je žádoucí zachovat anonymitu podepisujících. Například u elektronických voleb. Volič podepíše vybranou kandidátku, aniž by prozradil svou identitu. Volič může uplatnit jen jeden podpis, protože ty mají jednoznačný identifikátor a tak lze dohledat případné duplikáty.

## Důvěryhodnost, otevřenost, decentralizace

**Důvěryhodnost** podpisu je založena na asymetrické kryptografii. Při ní podepisující vlastní vždy pár klíčů - soukromý klíč a veřejný klíč. Se soukromým klíčem se podpis vytváří. Jen vlastník soukromého klíče může podpis vytvořit. Soukromý klíč tak nesmí být nikdy prozrazen. Naproti tomu veřejný klíč musí být předán všem k dispozici. Jen s pomocí veřejného klíče lze ověřit, že podpis je platný.
**Otevřenost** systému je zajištěna tak, že všechny údaje, kromě soukromých klíčů, jsou všem k dispozici - veřejné klíče podepisujích (voličů), dokumenty k podepsání (volební kandidátky) a podpisy. Kdokoliv si tak kdykoliv může ověřit, že kandidátky jsou podepsány daným seznamem veřejných klíčů a že tyto podpisy jsou platné. Systém tak nelze napadnout (hacknout), protože není žádný údaj, který by šel zmanipulovat, nebo tajemství, které by šlo vyzradit.
**Decentralizace** znamená, že nemusí nutně existovat centrální místo, na kterém se všechna data nachází. Data mohou být na více místech. Na jejich umístění nezáleží, protože jejich platnost si kdokoliv a kdykoliv může ověřit. Takto koncipovaný systém nelze vyřadit z činnosti, například útokem DDos.

## Kryptografie nad eliptickými křivkami

Pro sestavení podpisu se využívá [kryptografie eliptických křivek](https://cs.wikipedia.org/wiki/Kryptografie_nad_eliptickými_křivkami) (ECC), což je metoda [šifrování veřejných klíčů](https://cs.wikipedia.org/wiki/Asymetrická_kryptografie) založená na [algebraických strukturách](https://cs.wikipedia.org/wiki/Algebraická_struktura) [eliptických křivek](https://cs.wikipedia.org/wiki/Eliptická_křivka) nad [konečnými tělesy](https://cs.wikipedia.org/wiki/Konečné_těleso). K dispozici je několik typů křivek. Dále se při podpisu využívá [hashovací funkce](https://cs.wikipedia.org/wiki/Hašovací_funkce).

Typy křivek, které lze při podpisu použít:

| Název           | [OID](https://cs.wikipedia.org/wiki/Identifikátor_objektu) | Popis  |
| --------------- | --------------------- | ------------------------------------------- |
| prime256v1      | 1.2.840.10045.3.1.7   | X9.62/SECG curve over a 256 bit prime field |
| secp224r1       | 1.3.132.0.33          | NIST/SECG curve over a 224 bit prime field  |
| secp384r1       | 1.3.132.0.34          | NIST/SECG curve over a 384 bit prime field  |
| secp521r1       | 1.3.132.0.35          | NIST/SECG curve over a 521 bit prime field  |
| secp256k1*      | 1.3.132.0.10          | SECG curve over a 256 bit prime field       |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7  | RFC 5639 curve over a 256 bit prime field   |
| brainpoolP256t1 | 1.3.36.3.3.2.8.1.1.8  | RFC 5639 curve over a 256 bit prime field   |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | RFC 5639 curve over a 384 bit prime field   |
| brainpoolP384t1 | 1.3.36.3.3.2.8.1.1.12 | RFC 5639 curve over a 384 bit prime field   |
| brainpoolP512r1 | 1.3.36.3.3.2.8.1.1.13 | RFC 5639 curve over a 512 bit prime field   |
| brainpoolP512t1 | 1.3.36.3.3.2.8.1.1.14 | RFC 5639 curve over a 512 bit prime field   |


Typy hašovacích funkcí, které se při podpisu používají:

| Název     | [OID](http://www.oid-info.com/index.htm) | Popis                                    |
| --------- | ----------------------- | --------------------------------------------------------- |
| sha3-224* | 2.16.840.1.101.3.4.2.7  | [SHA3](https://cs.wikipedia.org/wiki/SHA-3)-224 algorithm |
| sha3-256* | 2.16.840.1.101.3.4.2.8  | SHA3-256 algorithm |
| sha3-384  | 2.16.840.1.101.3.4.2.9  | SHA3-384 algorithm |
| sha3-512  | 2.16.840.1.101.3.4.2.10 | SHA3-512 algorithm |

*) Pro křivku `secp256k1` lze použít pouze hash `sha3-224` nebo `sha3-256`. Viz [ScalarBaseMult can't handle scalars > 256 bits](https://github.com/ethereum/go-ethereum/blob/v1.9.25/crypto/secp256k1/curve.go#L249).


## Implementace

Projekt `Lirisi` je napsán v jazyce [Go](https://golang.org/) jako knihovna určená pro používání z jiných aplikací.
Součástí projektu jsou wrappery pro jazyky [Python](https://www.python.org/) a [Node.js](https://nodejs.org/).

## Použití projektu

```diff
- Upozornění: Projekt je ve vývoji. S použitím na produkci se doporučuje počkat na první vydání verze 1.0.0.
```

Projekt je koncipován primárně jako knihovna. Není určen pro běžného uživatele. Očekává se, že budou existovat klientské aplikace (frontendy) pro „koncové“ uživatele, které jej budou používat. Projekt nijak neřeší registraci účastníků, vytváření klíčů nebo jejich distribuci a ověřování. Přesto je součástí projektu i jednoduchá konzolová aplikace pro [příkazovou řádku](https://cs.wikipedia.org/wiki/Unixový_shell). Přes ni je možné celou funkcionalitu knihovny vyzkoušet. Vývojáři v Pythonu nebo v Node.js mohou knihovnu zkoušet přes připravené wrappery.

## Instalace

Pro nainstalování projektu je potřeba nejprve mít v systému nainstalován jazyk `Go`. Instalujte jej ze stránky [Go Downloads](https://golang.org/dl/). Po té se projekt nainstaluje příkazem `go get`:

```
$ go get github.com/zbohm/lirisi
```

Ti, kteří nechtějí instalovat jazyk `Go` a rovnou si aplikaci vyzkoušet, si mohou stáhnout z [Nightly.link](https://nightly.link/zbohm/lirisi/workflows/go/master) připravené binárky, zkompilované pro operační systémy `Windows`, `MacOS` a `Ubuntu`.


## Popis použití aplikace na příkazové řádce

Aplikace se volá příkazem `lirisi`:

```
$ lirisi

Lirisi is a command line tool for creating a "Linkable ring signature".
Version: 0.0.0 (pre-release)

Commands:

  genkey      - Generate EC private key.
  pubout      - Derive public key from private key.
  fold-pub    - Fold public keys into one file.
  sign        - Sign a message or file.
  verify      - Verify signature.
  key-image   - Output the linkable value to specify a new signer.
  pub-dgst    - Output the digest of folded public keys.
  pub-xy      - Outputs X,Y coordinates of public key (binary).
  restore-pub - Decompose public keys from folded file into separate files.
  list-curves - List of available curve types.
  list-hashes - List of available hash functions.
  help        - This help or help for a specific command.

Type "lirisi help COMMAND" for a specific command help. E.g. "lirisi help fold-pub".

For more see https://github.com/zbohm/lirisi.
```

### Výběr typu eliptické křivky a hašovací funkce

Skupina podepisujícíh se nejprve dohodne na typu eliptické křivky, kterou bude používat. Například `prime256v1`. Dále určí typ hašovací funkce, například `sha3-256`. Obě tyto hodnoty má aplikace `lirisi` nastaveny jako výchozí, takže se nemusí v jejích příkazech zadávat.

### Soukromý a veřejný klič + veřejné klíče ostatních

Nejdříve si každý účastník vytvoří svůj pár soukromého a veřejného klíče. Aplikace `lirisi` k tomuto účelu používá příkazy `genkey` a `pubout`.
Můžete ale použít například [openssl](https://www.openssl.org/). Vytváření klíčů přes `lirisi` je s `openssl` kompatibilní.

Vytvoření soukromého klíče:

```
$ lirisi genkey -out my-private-key.pem
```

nebo alternativně

```
$ openssl ecparam -genkey -name prime256v1 -noout -out my-private-key.pem
```

Vytvoření veřejného klíče:

```
$ lirisi pubout -in my-private-key.pem -out my-public-key.pem
```

nebo alternativně

```
$ openssl ec -pubout -in my-private-key.pem -out my-public-key.pem
```

Pro kruhový podpis je nezbytné mít k dispozici i veřejné klíče všech ostatních účastníků podpisu. Po té, co si každý účastník vytvoří svůj pár klíčů, pošle ten veřejný všem ostatním nebo jej nahraje do nějakého společného úložiště, ze kterého si jej ostatní stáhnou. V ukázce budeme simulovat stažení veřejných klíčů do složky `public-keys`.

Vytvoření veřejných klíčů do složky `public-keys`, jako kdyby byly stažené z úložiště nebo předané jiným způsobem.

```
$ mkdir public-keys
$ for name in Alice Bob Carol Dave Eve Frank George Helen Iva
do
  lirisi genkey | lirisi pubout -in - -out /tmp/public-keys/$name.pem
done
```

(nebo alternativně `openssl ecparam -name prime256v1 -genkey -noout | openssl ec -in - -pubout -out public-keys/$name.pem`)

K veřejným klíčům přidáme i svůj:

```
$ cp my-public-key.pem public-keys
```

Máme připraven soukromý klíč `my-private-key.pem` a složku `public-keys` se všemi veřejnými klíči, včetně našeho:

```
$ ls public-keys

Alice.pem  Bob.pem  Carol.pem  Dave.pem  Eve.pem  Frank.pem  George.pem  Helen.pem  Iva.pem  my-public-key.pem
```

Soukromý klíč vypadá takto:

```
$ cat my-private-key.pem

-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIApoL1M0U1wXM+YT7bF7y6RnBY9EwuGm02Dbr8IjuTyjoAoGCCqGSM49
AwEHoUQDQgAEa4WDUK4DCPMpNp5Wvmz+HZJ1thabxIv6Q/a68YxE58Lxd8HoQ2JF
7EX7pueGfeeQKznhzF25P8Qfe7SBs52LRw==
-----END EC PRIVATE KEY-----
```

Veřejný klíč pak vypadá takto:

```
$ cat my-public-key.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa4WDUK4DCPMpNp5Wvmz+HZJ1thab
xIv6Q/a68YxE58Lxd8HoQ2JF7EX7pueGfeeQKznhzF25P8Qfe7SBs52LRw==
-----END PUBLIC KEY-----
```


### Vytvoření souboru s veřejnými klíči

Před samotným podpisem se nejdříve musí vytvořit soubor s veřejnými klíči. Výsledný soubor s klíči je mnohem menší než prosté sloučení jejich obsahu, protože hodnoty se do něj ukládají v komprimované podobě. Navíc hodnoty společné pro všechny, jako je typ použité křivky, se do něj uloží jen jednou. Soubor s klíči tak má nejmenší možnou velikost. To má význam hlavně v případě velkého množství podepisujících. Nemusí si všichni předávat všechny veřejné klíče. Stačí, aby jeden z nich vytvořil tento soubor s klíči a nasdílel jej ostatním. Každý z účastníků obdrží jen jeden soubor, ve kterém má všechny veřejné klíče. Zde ovšem hrozí nebezpečí podvržení jiných klíčů, proto má každý takový soubor s klíči svůj unikátní otisk, podle kterého si každý může ověřit, že soubor skutečně obsahuje klíče podepisujících. Způsob ověření je popsán níže v kapitole [Obnova klíčů ze seznamu](#obnova-klicu).

Další důležitý aspekt seznamu klíčů je ten, že **na pořadí klíčů záleží!** Jednoznačnost podpisu se odvozuje právě z veřejných klíčů a z jejich pořadí. Je proto nezbytné se na pořadí dohodnout nebo je nějak stanovit. Aplikace `lirisi` implementuje metodu speciálního řazení, které je vždy zcela jednoznačné, ale přesto nepredikovatelné - nelze jej nijak předem odvodit. Nikdo z účastníků tedy nemůže pořadí ovlivnit. Podrobně je metoda popsána níže v kapitole [Řazení klíčů podle otisků](#razeni-klicu-podle-otisku).

Soubor s veřejnými klíči se vytváří příkazem `fold-pub`:

```
$ lirisi fold-pub -inpath public-keys -out folded-public-keys.pem
```

Výsledný soubor vypadá takto:

```
$ cat folded-public-keys.pem

-----BEGIN FOLDED PUBLIC KEYS-----
CurveName: prime256v1
CurveOID: 1.2.840.10045.3.1.7
Digest: 71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
HasherName: sha3-256
HasherOID: 2.16.840.1.101.3.4.2.8
NumberOfKeys: 10
Origin: github.com/zbohm/lirisi

MIIBvhMjZ2l0aHViLmNvbS96Ym9obS9saXJpc2kgUHVibGljIGtleXMGCCqGSM49
AwEHBglghkgBZQMEAggEIHGyl3I+cNmUhzXrZLBsfwW27DMckUqOstLwZhYuACY0
MIIBXgQhA4FkwtsTE51Bt8vDwvLqzOr9Wo/23Srlb/Htcnwh5l0nBCEDNFsxfvuo
3cnf5KUCySuifRlAoV7ZSb235MOTJIUaq7IEIQMwCLpQTQuup93hLvWPP/9fmgY1
mQepaNgI7UW1EAVRTwQhAxEG42wot9WoYnT4uEkG9/k04DsVCz7PnRxkD6wshoeG
BCECQLA/gChaoBiC0y2n/Cy2DmYxjAijsosLRGBkHK6fXNkEIQNrhYNQrgMI8yk2
nla+bP4dknW2FpvEi/pD9rrxjETnwgQhA/5d+KLKdDsz9as7gqVVUN9MiPhXgGcf
p5U9VORrbsctBCEDr97Q1TrQVTNukfiCmF/ofm2LmcrWRSF/6y2NJOJXDGkEIQPT
ERzuMDD//2xqCdLe4rEraudLNrjBpN6+1heLODkXWQQhA9/2pDlVKhyqnX3gZExy
fHL/t4pupI67lrX3DEcd78nL
-----END FOLDED PUBLIC KEYS-----
```

### Vytvoření podpisu

Podpis se vytváří příkazem `sign`. Můžeme podepsat buď nějaké prohlášení nebo soubor.

Příklad podepsání textu `Hello, world!`:

```
$ lirisi sign -message 'Hello, world!' -inpub folded-public-keys.pem -inkey my-private-key.pem -out signature.pem
```

Vznikne takovýto podpis:

```
$ cat signature.pem

-----BEGIN RING SIGNATURE-----
CurveName: prime256v1
CurveOID: 1.2.840.10045.3.1.7
HasherName: sha3-256
HasherOID: 2.16.840.1.101.3.4.2.8
KeyImage:
  1a:3a:56:52:0b:a2:20:42:2b:ec:85:44:eb:6a:3e:2e
  29:00:16:2c:4b:6f:7d:67:7f:ba:e7:9d:2b:5f:83:fa
  b1:b6:16:10:9a:9c:8e:76:f4:cd:63:3f:86:93:cd:04
  fe:06:14:45:9a:1e:d9:1d:56:d2:25:77:de:1e:dd:02
NumberOfKeys: 10
Origin: github.com/zbohm/lirisi

MIIB+xMhZ2l0aHViLmNvbS96Ym9obS9saXJpc2kgU2lnbmF0dXJlAgEBBggqhkjO
PQMBBwYJYIZIAWUDBAIIMEQEIBo6VlILoiBCK+yFROtqPi4pABYsS299Z3+6550r
X4P6BCCxthYQmpyOdvTNYz+Gk80E/gYURZoe2R1W0iV33h7dAgQgUxoLYy+XcTCv
WJ/NS/Ofrc3XplMNaJxHWjxz9YfNvREwggFUBCBXZ3h6ePkNskKv6FYZ1/3HZOzA
KonhaNsuKbXT4Ljy2gQgCCBqEXoSG5OV3lMKUwc4QbhwkUuLYwQXMRgRuuB8crIE
IAPyph3mY+qyeMtsG42ec+HCR7Xzb+mUH7I5ka4xTf73BCB7zGdfkjsBnXaXPE8i
7PXhYKDyamfLmzFS6HOm/0Af2AQgQnpZywoZJbZfU2Xql1CCI9+NYWpsPFYba5tz
4IsnC4MEIP5DBw97peW2tcDzOHU00JtvNegVGj1Ci21ky2Ifd+62BCCJowQl+b4C
oaCs7cf7nqnfYLR64lP7PY/kX+7olHiw9gQgTu00L2HOz6BQ0+S5ODJ9dOWd7U8g
+ysanafTF2weh7cEIN2ltMDOWbenRaOeG3T3Z5JxP4fyItb62fhbQZGdf9wdBCAf
2RtfJtVdZp/+To1GD69Boiqos81hlDymMs4fufdLSg==
-----END RING SIGNATURE-----
```

Pokud je potřeba podepsat nějaký dokument, tak se v parametru `-message` uvede jeho název. Například: `-message ./path/document.pdf`.

#### Parametr `case` pro rozlišování duplicitních podpisů

Rozpoznání duplicitních podpisů (jednoznačnost podepisujícího) je založeno na porovnání seznamu veřejných klíčů. Aby bylo možné při hlasování vytvořit více neduplicitních podpisů, tak lze při podepisování přes parametr `-case` nastavit nějakou hodnotu, která duplicitě pro daný seznam zabrání. Například se to může použít při vícekolovém hlasování. Pak bude jednoznačnost existovat jen pro dané kolo a účastník tak může vytvořit pro každé kolo jeden podpis:

```
$ lirisi sign -message 'Hello, world!' -case 'První hlasovací kolo' ...
$ lirisi sign -message 'Hello, world!' -case 'Druhé hlasovací kolo' ...
```

### Ověření kruhového podpisu

Podpis se ověřuje příkazem `verify`:

```
$ lirisi verify -message 'Hello, world!' -inpub folded-public-keys.pem -in signature.pem
Verified OK

$ lirisi verify -message 'Hello, world?' -inpub folded-public-keys.pem -in signature.pem
Verification Failure
```

### Vstupní/výstupní formáty PEM a DER

Výchozí formát pro soubor s klíči a podpis je [PEM](https://cs.wikipedia.org/wiki/PEM). Je to textový formát, vhodný například pro ukládání do databáze. Kromě něj je možné použít i binární soubor [DER](https://cs.wikipedia.org/wiki/Basic_Encoding_Rules#Kódování_DER). Formát nastavíte parametrem `-format`, například: `-format DER`.
Do formátu `DER` může být uložen i soukromý a veřejný klíč, vegenerovaný přes `openssl`. Apliakce jej rozpozná a umí jej načíst.

### Hodnota KeyImage pro určení duplicity podepisujícího

Hodnota `KeyImage` v podpisu určuje jednoznačně podepisujícího. Je to de facto anonymní unikátní identifikátor podepisujícího. Ve formátu `PEM` se zobrazuje za názvem `KeyImage`:

```
$ cat signature.pem

-----BEGIN RING SIGNATURE-----
  ...
KeyImage:
  1a:3a:56:52:0b:a2:20:42:2b:ec:85:44:eb:6a:3e:2e
  29:00:16:2c:4b:6f:7d:67:7f:ba:e7:9d:2b:5f:83:fa
  ....
```

To je ovšem jen prostý text, který by mohl být podvržen. Věrohodný údaj se z podpisu vyčte příkazem `key-image`:

```
$ lirisi key-image -in signature.pem

1a3a56520ba220422bec8544eb6a3e2e290016...
```

Takto zobrazená hodnota je pro člověka špatně čitelná, proto je možné do ní přes parametr `-c` přidat oddělovač:

```
$ lirisi key-image -c -in signature.pem

1a:3a:56:52:0b:a2:20:42:2b:ec:85:44:eb:6a:3e:2e:29:00:16...
```

### Otisk seznamu klíčů

Seznam klíčů má také svůj jedinečný otisk, podle kterého je možné jej identifikovat. Zobrazuje se za názvem `Digest`:

```
$ cat folded-public-keys.pem

-----BEGIN FOLDED PUBLIC KEYS-----
  ...
Digest: 71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
  ...
```

Stejně jako u podpisu, i tato hodnota je ovšem jen prostý text, který by mohl být podvržen. Věrohodný údaj se vypíše příkazem `pub-dgst`:

```
$ lirisi pub-dgst -in folded-public-keys.pem
71b297723e70d9948735eb64b06c7f05b6ec331c914a8eb2d2f066162e002634

$ lirisi pub-dgst -c -in folded-public-keys.pem
71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
```

### <a name="obnova-klicu">Obnova klíčů ze seznamu</a>

Při podezření, že seznam klíčů je zmanipulován, je možné klíče ze seznamu vyjmout a obnovit je do původních samostatných souborů. Pak lze každý z nich porovat s původním klíčem, jestli je shodný. Obnova klíčů se provede příkazem `restore-pub`. Soubory se uloží do vybrané složky, například `restored-keys`. Výchozí formát je `PEM`.

```
$ mkdir restore-pub
$ lirisi restore-pub --in folded-public-keys.pem -outpath restore-pub
10 public keys saved into restore-pub.
```

Původní klíče jsou ve složce `public-keys`. Shodu zjistíme porovnáním obsahů všech souborů v těchto dvou složkách. Podle jmen souborů to udělat nelze, neboť ty se při sloučení do seznamu neukládají.

```
$ find public-keys -type f -exec md5sum {} + > dir1.txt
$ find restore-pub -type f -exec md5sum {} + > dir2.txt

$ while read line
do
  hash=`echo $line | awk '{print $1}'`
  name=`echo $line | awk '{print $2}'`
  sed -i "s|$hash |$hash $name|" dir1.txt
done < dir2.txt

$ cat dir1.txt

500ece1452eae81d60880e635e639dbc restore-pub/public-key-03.pem public-keys/Bob.pem
3b57281818eda2af1f0f5d71105dfb57 restore-pub/public-key-04.pem public-keys/Helen.pem
c50decd521cf9902b8da7958ce02896d restore-pub/public-key-08.pem public-keys/George.pem
07b7aec69e5d516aceb77f46700f8986 restore-pub/public-key-02.pem public-keys/Alice.pem
879412e39f9c375f2add8f3426e37f2b restore-pub/public-key-10.pem public-keys/Eve.pem
b6ef9d09ed72aeb4026ee22e820e3371 restore-pub/public-key-05.pem public-keys/Iva.pem
93c63ffc3bd0fd42f3906fd1c52d9023 restore-pub/public-key-01.pem public-keys/Frank.pem
5dd7f5ae325977c18f63b6a30497fddd restore-pub/public-key-07.pem public-keys/Carol.pem
e0dfa849d907cc6f725bafc532111a9b restore-pub/public-key-06.pem public-keys/my-public-key.pem
58e06bf36bea38092218f1aab548b38e restore-pub/public-key-09.pem public-keys/Dave.pem
```

### <a name="razeni-klicu-podle-otisku">Řazení klíčů podle otisků</a>

Pořadí veřejných klíčů je důležité, neboť se podle něj určují identifikátory podepisujících. Pravidlo pro určení pořadí klíčů musí být jednoznačné. Dále by mělo být co nejméně ovlivnitelné, aby nebylo možné pořadí nějak zmanipulovat. Příkaz `fold-pub` provádí ve výchozím nastavení setřídění klíčů podle otisků hodnot X, Y veřejných klíčů. Otisk pro řazení je opatřen hodnotu „salt“ vypočtenou ze seznamu otisků všech klíčů. Setřídit klíče tak lze pouze tehdy, pokud všechny existují.

Soubor s klíči `folded-public-keys.pem` má otisk `71b297723e70d9948735...`:

```
$ cat folded-public-keys.pem

-----BEGIN FOLDED PUBLIC KEYS-----
  ...
Digest: 71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
HasherName: sha3-256
  ...
```

Výpočet otisku je možné zreprodukovat i v [Bash](https://cs.wikipedia.org/wiki/Bash) na [příkazovém řádku](https://cs.wikipedia.org/wiki/Unixový_shell). Z výpisu hodnoty `HasherName` vidíme, že byla použita hashovací funkce `sha3-256`. Proto pro výpočty otisků budeme používat tuto funkci.

Hodnoty X, Y jsou souřadnice bodu na eliptické křivce. Z těchto dvou čísel se skládá veřejný klíč. Bajty těchto dvou čísel lze vypsat příkazem `pub-xy`. Protože se jedná o binární data, tak si je na konzoli můžeme interpretovat přes filtr `hexdump`:

```
$ lirisi pub-xy -in my-public-key.pem | hexdump -C

00000000  04 6b 85 83 50 ae 03 08  f3 29 36 9e 56 be 6c fe  |.k..P....)6.V.l.|
00000010  1d 92 75 b6 16 9b c4 8b  fa 43 f6 ba f1 8c 44 e7  |..u......C....D.|
00000020  c2 f1 77 c1 e8 43 62 45  ec 45 fb a6 e7 86 7d e7  |..w..CbE.E....}.|
00000030  90 2b 39 e1 cc 5d b9 3f  c4 1f 7b b4 81 b3 9d 8b  |.+9..].?..{.....|
00000040  47                                                |G|
```

Program `openssl` umí bajty veřejného klíče vypsat jen ze soukromého klíče. Pro veřejný klíč bez znalosti soukromého se musí použít `pub-xy` nebo jiná utilita.

```
$ openssl ec -text -noout -in my-private-key.pem

read EC key
Private-Key: (256 bit)
priv:
    0a:68:2f:53:34:53:5c:17:33:e6:13:ed:b1:7b:cb:
    a4:67:05:8f:44:c2:e1:a6:d3:60:db:af:c2:23:b9:
    3c:a3
pub:
    04:6b:85:83:50:ae:03:08:f3:29:36:9e:56:be:6c:
    fe:1d:92:75:b6:16:9b:c4:8b:fa:43:f6:ba:f1:8c:
    44:e7:c2:f1:77:c1:e8:43:62:45:ec:45:fb:a6:e7:
    86:7d:e7:90:2b:39:e1:cc:5d:b9:3f:c4:1f:7b:b4:
    81:b3:9d:8b:47
ASN1 OID: prime256v1
NIST CURVE: P-256
```

Z těchto dvou výpisů můžete ověřit shodu - že se opravdu jedná o bajty veřejného klíče:

```
00000000  04 6b 85 83 50 ae 03 08  f3 29 36 9e 56 be 6c fe  |.k..P....)6.V.l.|
pub:      04:6b:85:83:50:ae:03:08: f3:29:36:9e:56:be:6c:fe:
```

Vytvoříme tedy seznam s otisky veřejných klíčů a setřídíme jej podle nich:

```
$ for pkey in public-keys/*
do
    lirisi pub-xy -in $pkey | openssl dgst -sha3-256 - | awk '{print $2}'
done > public-keys-hashes.txt

$ LC_ALL=C sort public-keys-hashes.txt > sorted-hashes.txt
```

V souboru `sorted-hashes.txt` máme seznam, ze kterého získáme otisk, který uložíme do proměnné `summary`:

```
$ summary=`openssl dgst -sha3-256 sorted-hashes.txt | awk '{print $2}'`
```

Hodnotu `summary` použijeme jako „salt“. Spojíme ji s otiskem každého klíče. Z takto spojené hodnoty vytvoříme nový otisk. Podle tohoto nového otisku se pak klíče setřídí.

Vytvoření nových otisků se `summary` jako „salt“:

```
$ while read code
do
    digest=`echo -n $summary$code | openssl dgst -sha3-256 | awk '{print $2}'`
    echo "$digest $code"
done < public-keys-hashes.txt > digests.txt
```

Setřídění klíčů podle nových otisků a výpočet finálního otisku pro složené klíče:

```
$ LC_ALL=C sort digests.txt | awk '{print $2}' | openssl dgst -sha3-256 -c | awk '{print $2}'
71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
```

Tato hodnota odpovídá údaji `Digest` v souboru s klíči a výpisu z příkazu `pub-dgst`:

```
$ lirisi pub-dgst -c -in folded-public-keys.pem
71:b2:97:72:3e:70:d9:94:87:35:eb:64:b0:6c:7f:05:b6:ec:33:1c:91:4a:8e:b2:d2:f0:66:16:2e:00:26:34
```

### Setřídění klíčů podle jejich otisků

```
$ for key in public-keys/*
do
    name=`basename $key`
    code=`lirisi pub-xy -in $key | openssl dgst -sha3-256 - | awk '{print $2}'`
    digest=`echo -n $summary$code | openssl dgst -sha3-256 | awk '{print $2}'`
    echo "$digest $name"
done > digest-public-keys.txt

$ LC_ALL=C sort digest-public-keys.txt | awk '{print $2}'

Frank.pem
Alice.pem
Bob.pem
Helen.pem
Iva.pem
my-public-key.pem
Carol.pem
George.pem
Dave.pem
Eve.pem
```

Pořadí klíčů odpovídá seznamu, který jsme získali při [obnově klíčů](#obnova-klicu):

```
$ awk '{print $2 " " $3}' dir1.txt | sort | awk '{print $2}'

public-keys/Frank.pem
public-keys/Alice.pem
public-keys/Bob.pem
public-keys/Helen.pem
public-keys/Iva.pem
public-keys/my-public-key.pem
public-keys/Carol.pem
public-keys/George.pem
public-keys/Dave.pem
public-keys/Eve.pem
```


## Knihovna

Příklad použití knihovny v jazyce `Go`:

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"log"

	"github.com/zbohm/lirisi/client"
	"github.com/zbohm/lirisi/ring"
)

func encodePublicKeyToDer(key *ecdsa.PublicKey) []byte {
	derKey, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return derKey
}

// Auxiliary function for creating public keys.
func createPublicKeyList(curve elliptic.Curve, size int) []*ecdsa.PublicKey {
	publicKeys := make([]*ecdsa.PublicKey, size)
	for i := 0; i < size; i++ {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		publicKeys[i] = privateKey.Public().(*ecdsa.PublicKey)
	}
	return publicKeys
}

func createPrivateAndPublicKeyExample() {
	// Create private key
	status, privateKey := client.GeneratePrivateKey("prime256v1", "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", privateKey)
	// Create public key.
	status, publicKey := client.DerivePublicKey(privateKey, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("%s", publicKey)
}

func baseExample(
	curveType func() elliptic.Curve,
	hashFnc func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	publicKeys []*ecdsa.PublicKey,
	message, caseIdentifier []byte,
) ([]byte, []byte) {
	// Make signature.
	status, signature := ring.Create(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}

	// Verify signature.
	status = ring.Verify(signature, publicKeys, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature verified OK")
	} else {
		fmt.Println("Signature verification Failure")
	}

	// Encode signature to format DER.
	status, signatureDer := client.EncodeSignarureToDER(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER:\n%s\n", hex.Dump(signatureDer))

	// Encode signature to format PEM.
	status, signaturePem := client.EncodeSignarureToPEM(signature)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n%s\n", signaturePem)
	return signatureDer, signaturePem
}

func foldedKeysExample(privateKey *ecdsa.PrivateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier []byte) {
	// Verify signature in DER.
	status := client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER: Verified OK")
	} else {
		fmt.Println("Signature in DER: Verification Failure")
	}
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM: Verified OK")
	} else {
		fmt.Println("Signature in PEM: Verification Failure")
	}

	// Encode private key to DER.
	privateKeyDer, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	// Make first signature in format DER.
	status, signatureDer = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "DER")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in DER Nr.2:\n\n%s\n", hex.Dump(signatureDer))
	// Verify signature in DER.
	status = client.VerifySignature(foldedPublicKeys, signatureDer, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in DER Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in DER Nr.2: Verification Failure")
	}

	// Make second signature in format PEM.
	status, signaturePem = client.CreateSignature(foldedPublicKeys, privateKeyDer, message, caseIdentifier, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Signature in PEM:\n\n%s\n", signaturePem)
	// Verify signature in PEM.
	status = client.VerifySignature(foldedPublicKeys, signaturePem, message, caseIdentifier)
	if status == ring.Success {
		fmt.Println("Signature in PEM Nr.2: Verified OK")
	} else {
		fmt.Println("Signature in PEM Nr.2: Verification Failure")
	}
	fmt.Println()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Choose curve type.
	curveType := elliptic.P256
	// Choose hash type.
	hashName := "sha3-256"
	hashFnc, ok := ring.HashCodes[hashName]
	if !ok {
		log.Fatal(ring.UnexpectedHashType)
	}

	createPrivateAndPublicKeyExample()

	// Creating public keys as a simulation of keys supplied by other signers.
	publicKeys := createPublicKeyList(curveType(), 9)

	// Create your private key.
	privateKey, err := ecdsa.GenerateKey(curveType(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	// Add your public key to other public keys.
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	publicKeys = append(publicKeys, publicKey)

	status, coordinates := client.PublicKeyXYCoordinates(encodePublicKeyToDer(publicKey))
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Coordinates of public key:\n%s\n", hex.Dump(coordinates))

	message := []byte("Hello world!")
	caseIdentifier := []byte("Round Nr.1")

	signatureDer, signaturePem := baseExample(curveType, hashFnc, privateKey, publicKeys, message, caseIdentifier)

	// Encode public keys to DER.
	publicKeysDer := [][]byte{}

	for _, key := range publicKeys {
		publicKeysDer = append(publicKeysDer, encodePublicKeyToDer(key))
	}

	// Create the content of file with public keys.
	status, foldedPublicKeys := client.FoldPublicKeys(publicKeysDer, hashName, "DER", "notsort")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Public keys in DER:\n%s\n", hex.Dump(foldedPublicKeys))
	// Display fingerprint of public keys in format PEM.
	status, digest := client.PublicKeysDigest(foldedPublicKeys, true)
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Public keys digest: %s\n\n", digest)

	// Display fingerprint of public keys in format DER.
	status, foldedPublicKeysPEM := client.FoldPublicKeys(publicKeysDer, hashName, "PEM", "notsort")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	fmt.Printf("Keys from DER:\n%s\n", foldedPublicKeysPEM)

	foldedKeysExample(privateKey, foldedPublicKeys, signatureDer, signaturePem, message, caseIdentifier)

	// Decompose folded public keys into files.
	status, unfoldedPublicKeys := client.UnfoldPublicKeysIntoBytes(foldedPublicKeys, "PEM")
	if status != ring.Success {
		log.Fatal(ring.ErrorMessages[status])
	}
	for i, pubKey := range unfoldedPublicKeys {
		fmt.Printf("%d. public key:\n%s\n", i+1, pubKey)
	}
}
```

### Knihovna pro jiné programovací jazyky

Pro použití v jiných programovacích jazycích je připravena knihovna [lib/lirisilib.go](https://github.com/zbohm/lirisi/blob/master/lib/lirisilib.go).
Je potřeba ji zkompilovat s přepínačem `-buildmode=c-shared`. Tím se vygeneruje binárka a hlavičkový soubor:

```
$ go build -o wrappers/lirisilib.so -buildmode=c-shared lib/lirisilib.go
```

Pro tuto knihovnu má `lirisi` připraveny wrappery, pro jazyk [Python](https://www.python.org/) (>=3.5) 
a pro [Node.js](https://nodejs.org/).

#### Python

Wrapper pro [Python](https://www.python.org/) (verze >= 3.5) je připraven ve složce `wrappers/python/lirisi/`.
Před prvním použitím si do něj binárku zkopírujte nebo na ni odkažte v symlinku:

```
$ ln -s ../../lirisilib.so wrappers/python/lirisi/lirisilib.so
```

V souboru `example.py` je ukázka použití. Ta vyžaduje modul `cryptography`.
Pokud jej nemáte nainstalován, tak si jej nainstalujte, např. přes `pip install cryptography`.

Jděte do složky `wrappers/python` a spusťte ukázku: `python example.py`:

```python
from typing import Callable, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lirisi import (CreateSignature, DerivePublicKey, FoldPublicKeys,
                    GeneratePrivateKey, LirisiException, PublicKeysDigest,
                    PublicKeyXYCoordinates, SignatureKeyImage,
                    UnfoldPublicKeys, VerifySignature)


def createPublicKeyList(backend: Callable, curve: ec.EllipticCurve, size: int) -> List[bytes]:
    public_keys_pem = []
    for i in range(size):
        private_key = ec.generate_private_key(curve, backend)
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_keys_pem.append(pem)
    return public_keys_pem


def main():
    backend = default_backend()

    # Create private key. Default curve type is "prime256v1".
    priateKeyPem = GeneratePrivateKey()
    print(priateKeyPem.decode())

    # Create public key.
    publicKeyPem = DerivePublicKey(priateKeyPem)
    print(publicKeyPem.decode())

    # Choose curve type.
    curve = ec.SECP256R1()

    # Creating public keys as a simulation of keys supplied by other signers.
    public_keys_pem = createPublicKeyList(backend, curve, 9)

    # Create your private key.
    private_key = ec.generate_private_key(curve, backend)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(private_key_pem.decode())

    # Add your public key to other public keys.
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    public_keys_pem.append(public_key_pem)

    coordinates = PublicKeyXYCoordinates(public_key_pem)
    print("Public key coordinates (bytes):\n", coordinates, "\n")

    # Create the content of file with public keys.
    foldedPublicKeys = FoldPublicKeys(public_keys_pem)
    print(foldedPublicKeys.decode())

    # Display fingerprint of public keys.
    digest = PublicKeysDigest(foldedPublicKeys, True)
    print("Public keys digest:", digest.decode())
    print()

    # Make signature.
    signature = CreateSignature(foldedPublicKeys, private_key_pem, b'Hello, world!')
    print(signature.decode())

    # Verify signature.
    if VerifySignature(foldedPublicKeys, signature, b'Hello, world!'):
        print("Signature verified OK")
    else:
        print("Signature verification Failure")
    print()

    # Display Signer identifier KeyImage.
    key_image = SignatureKeyImage(signature, True)
    print("KeyImage:", key_image)
    print()

    unfolded_keys = UnfoldPublicKeys(foldedPublicKeys)
    for pos, key in enumerate(unfolded_keys):
        print("public-key-{:>02d}.pem".format(pos + 1))
        print(key.decode())


if __name__ == "__main__":
    try:
        main()
    except LirisiException as err:
        print(err)
```

#### Node.js

Wrapper pro [Node.js](https://nodejs.org/) je připraven ve složce `wrappers/nodejs/lirisi/`.
Před prvním použitím si do něj binárku zkopírujte nebo na ni odkažte v symlinku:

```
$ ln -s ../../lirisilib.so wrappers/nodejs/lirisi/lirisilib.so
```

V souboru `example.js` je ukázka použití.
Jděte do složky `wrapper/nodejs`:

```
$ cd wrappers/nodejs
```

Před prvním spuštěním si nainstalujte potřebné balíky:

```
$ npm install
```

Poznámka: Pokud se vám při instalaci vypíše chyba `npm ERR! ref@1.3.5 install: node-gyp rebuild`, tak zkuste svůj OS zaktualizovat:

```
npm install --global npm@latest
npm install --global node-gyp@latest
npm config set node_gyp $(npm prefix -g)/lib/node_modules/node-gyp/bin/node-gyp.js
```

Nyní již můžete spustit ukázku:

```
$ node example.js
```

```javascript
var Eckles = require('eckles')
const lirisi = require('lirisi')


const main = async () => {
    // Create private key.
    const privatePem = lirisi.GeneratePrivateKey("prime256v1")
    console.log("Curve type prime256v1:\n", lirisi.ArrayToString(privatePem))

    // Create public key.
    const publicPem = lirisi.DerivePublicKey(privatePem)
    console.log(lirisi.ArrayToString(publicPem))

    // Creating public keys as a simulation of keys supplied by other signers.
    const publicKeysPEM = []
    for (let i = 0; i < 9; i++) {
        const pair = await Eckles.generate({format: 'pem'})
        publicKeysPEM.push(pair.public)
    }

    // Create your private and public key.
    const pair = await Eckles.generate({format: 'pem'})
    const privateKeyPEM = pair.private
    const publicKeyPEM = pair.public
    console.log("Eckles.generate:\n", privateKeyPEM, "\n")

    const coordinates = lirisi.PublicKeyXYCoordinates(publicKeyPEM)
    console.log("Puplic key coordinates:\n", Buffer.from(coordinates).toString('hex'), "\n")

    // Add your public key to other public keys.
    publicKeysPEM.push(publicKeyPEM)

    // Create the content of file with public keys.
    const foldedPublicKeys = lirisi.FoldPublicKeys(publicKeysPEM)
    console.log(lirisi.ArrayToString(foldedPublicKeys))

    // Display fingerprint of public keys.
    console.log("Digest:", lirisi.PublicKeysDigest(foldedPublicKeys, true), "\n")

    const message = 'Hello, world!'

    // Make signature.
    const signature = lirisi.CreateSignature(foldedPublicKeys, privateKeyPEM, message)
    console.log(lirisi.ArrayToString(signature))

    // Verify signature.
    const result = lirisi.VerifySignature(foldedPublicKeys, signature, message)
    console.log(lirisi.ResultMessage(result), "\n")

    console.log("KeyImage:", lirisi.SignatureKeyImage(signature, true), "\n")

    const unfoldedPublicKeys = lirisi.UnfoldPublicKeys(foldedPublicKeys)
    for(let i = 0; i < unfoldedPublicKeys.length; i++) {
        console.log(
            'public-key-' + (i + 1).toString().padStart(2, "0") + '.pem\n',
            lirisi.ArrayToString(unfoldedPublicKeys[i])
        )
    }
}

main().catch((e) => {
    console.error(e)
})
```

### Prohlížení kódu

Některé zdrojové kódy ve stylu „Literate programming“ jsou k dispozici na https://zbohm.github.io/lirisi/. Popis implementace podpisu podle schematu je v sekci [4 A LSAG Signature Scheme](https://zbohm.github.io/lirisi/signature_factory.html#section-25).


### Licence

Viz [LICENCE](/LICENSE).
