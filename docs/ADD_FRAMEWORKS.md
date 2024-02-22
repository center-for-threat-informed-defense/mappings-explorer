# Add Mappings Frameworks

**Table of Contents:**

- [Add a New Mappings Framework](#add-a-new-mappings-framework)
- [Add a New Version Combination](#add-mappings-frameworks)
- [Add a New ATT&CK Version](#add-a-new-attck-version)

## Add a New Mappings Framework

Mappings Explorer is designed to have additional mappings projects added in the future. Follow these steps to add a new project on the website.

1. Add mappings source files in `src/mapex_convert/mappings`
2. Add new parser in `src/mapex_convert` to convert mappings files into the unified schema
3. Define new project in `load_projects()` function in `site_builder.py` and add all the appropriate information, including framework description, versions, and any resources that will be downloadable from the website (ex. scope documentation). Try to make the framework description roughly the same length as the ones for the other projects in order to make the homepage look as cohesive as possible.
4. Add new project to nav bar (`_navigation`) and footer (`_footer`)
5. Write function to get capability descriptions, if necessary. Some projects (security stack) have capability descriptions in the mappings source files. Other projects (CVE and NIST) have description dictionaries built from API calls.

## Add a New Version Combination

In future mappings projects, coverage of existing projects should increase. Follow these steps to add a new version combination to an existing mapping framework.

1. Add new mappings file in `src/mapex_convert/mappings`
2. If going from one possible version to multiple, adjust the project parser as necessary as the parser may not be set up to look for multiple versions
3. Add version combinations to project's validVersions array

## Add a New ATT&CK Version

As future ATT&CK versions get released, new ATT&CK versions will need to be added to the website.

All that is needed to add future ATT&CK versions is to update the `all_attack_versions` and `attack_domains` variables in `site_builder.py`, being sure to update the matrix-specific versions of those variables as well in `build_matrix`. ATT&CK versions that don't have any mappings will not have pages built out for them but the matrix view will be available.
