# PackerGrind
A valgrind plugin for adaptive unpacking of Android applications.

It is implemented based on valgrind-3.11.0 provided by the AOSP project of Android 6.0.1 (#src#/external/valgrind).

The implementation including following two major parts: extensions of coregrind and implementation of packergrind.

Because the extensions of coregrind is done when I interned in a security company,
I cannot release this part code according to the requirement of the company.
To facilite the re-implementation of the extensions of coregrind, 
I introduce the major extensions of coregrind as follows.

Extension of coregrind (The core part of Valgrind).
    coregrind of Vagrind has been extended through following aspects:
    1.1 We have extended the ELF parsing part of Valgrind. 
            
            Since Valgrind focuses on the analysis of normal programs, 
            it could crash when the ELF format of the library files are invalid, 
            however, most of the malware make their library files with invalid ELF formats to impede analysis. 

    1.2 We have extended the ARM instruction translation part of Valgrind.
            
            Malware could protect themselves through inserting invalid instructions or specific instructions,
            but Valgrind could crash during the translation of these instructions,
            hence we have extended Valgrind to avoid crash when special instructions are translated.

    1.3 We have extended the signal process module of Valgrind.

            Since Valgrind is not designed for Android system originally,
            crash happen frequently when it is used to analyze Android apps.
            We have extended signal process module of Valgrind to avoid crash
            when crash signals are generated.

    1.4 We have extended the stack management module of Valgrind.

            Since the stacks allocated for Android (Java) applications are always with big sizes, 
            and Valgrind is originally designed for analyzing native programs,
            of which the stack sizes are much smaller.
            To reduce crashes when Valgrind is used to analyze Android apps,
            we have extended Valgrind to allocate large size of stack when it is used for Android apps.

    1.5 Finally, we also have extended Valgrind to identify OAT files.
