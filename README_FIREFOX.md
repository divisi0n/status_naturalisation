# Installation Firefox — Statut Naturalisation

## Fichiers modifiés par rapport à la version Chrome
- `manifest.json` — ajout du `browser_specific_settings.gecko` (gecko ID + version min Firefox 109)
- `inject.js` — ajout d'un fallback `browser.*` / `chrome.*` pour la compatibilité cross-browser

## Étapes d'installation

### Option 1 — Temporaire (sans redémarrage)
1. Ouvre Firefox et va sur : `about:debugging#/runtime/this-firefox`
2. Clique sur **"Charger un module complémentaire temporaire…"**
3. Navigue dans le dossier de l'extension et sélectionne le fichier **`manifest.json`**
4. L'extension est active jusqu'au prochain redémarrage de Firefox

### Option 2 — Permanente (Firefox Developer Edition ou Nightly uniquement)
1. Ouvre Firefox Developer Edition / Nightly
2. Va sur : `about:config`
3. Cherche `xpinstall.signatures.required` et passe-le à **`false`**
4. Va sur `about:addons` → icône engrenage → **"Installer un module depuis un fichier"**
5. Sélectionne le fichier `.zip` de l'extension (renommé en `.xpi`)

## Notes
- `content.js` et `forge.min.js` : copier tels quels depuis la version Chrome originale
- Les icônes : copier le dossier `icons/` tel quel
- Firefox 109+ requis (premier Firefox avec support complet Manifest V3)
