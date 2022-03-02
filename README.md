![]()

SIEM open source, analyse de vulnérabilité, Host- & Network-IDS. Le tout enveloppé dans une application Web Python moderne et expédié dans des conteneurs Docker.
La CBox s'appuie sur des blocs solides comme Elastic Stack, OpenVAS et Suricata pour fournir des informations sur la sécurité. De plus, il propose une mise à jour en un clic, une installation automatisée, une configuration facile via un assistant initial et un modèle d'autorisation basé sur les rôles pour l'accès Web et API. 

Nous vous invitons à l'essayer et à assurer la sécurité de votre réseau.


# Install
Nous proposons une méthode d'installation automatisée via un script bash.

**Actuellement, seul Ubuntu 20.04 LTS Server est pris en charge et testé.** 

Remarque : Bien que le script d'installation soit conçu pour avoir le même résultat à chaque exécution (idempotence), il est recommandé de lancer l'installation depuis une console stable. Nous vous recommandons de l'exécuter dans une session `screen`.

Avant de démarrer l'installation, assurez-vous qu'à l'état actuel, le script d'installation inclut les modifications système suivantes:

* De nouveaux packages seront installés pour résoudre les dépendances.
* Un nouveau dossier `/data` sera créé dans votre répertoire racine. Le dossier sert au stockage des données des alertes et des flux Elasticsearch et Suricata.
* Un nouvel utilisateur sudo appelé `cboxadmin` sera créé sur le système.
* Le service CBox sera activé.
* Le serveur de noms des systèmes sera défini sur le serveur DNS proxy inclus dans CBox. Il peut être configuré à l'aide de l'assistant initial.
* La CBox sera installée dans `/opt/cbox/` et ses configurations seront copiées à partir du dossier de dépôt cloné `/etc/cbox`.

Après le clonage, vous devez modifier et remplacer les informations d'identification par défaut dans:
* `config/secrets/*.conf`
* `docker/elastalert/etc/elastalert/smtp_auth_file.yaml`

Une fois que vous êtes prêt, l'installation est aussi simple que: 
```
git clone https://github.com/CyberHackFR/cbox.git
# Modifiez les fichiers de configuration avant d'exécuter install.sh!
sudo /bin/bash /cbox/scripts/Automation/install.sh
```

Le script peut vous poser quelques questions et vous informera de la progression.

Une fois l'opération terminée, accédez à `https://SERVEUR_IP`

# Contribuer
## Notre Philosophie

CBox a commencé comme un produit interne, développé ici chez CyberHack.
Il est utilisé dans les évaluations de sécurité des réseaux des clients tout en permettant une installation permanente dans l'environnement.  

En optant pour l'open source, nous n'avons plus caché la pile logicielle au public et souhaitons à la place nous engager avec la communauté de la sécurité. Tout le monde est libre de contribuer et de créer un fork de ce référentiel. Comme pour tous les produits, nous vous demandons de respecter la licence. Bien que tout le monde soit libre d'utiliser le produit à des fins commerciales, nous vous demandons de bien vouloir contribuer en arrière en créant des demandes d'extraction en amont. De cette façon, tous les utilisateurs de la CBox peuvent évaluer.

Nous sommes également ravis de vous aider à démarrer avec le référentiel et à y contribuer!
N'hésitez pas à contacter nos ingénieurs en déposant un [email](mailto:box@cyberhack.fr) dans notre boîte aux lettres.

Assez souvent, des problèmes plus petits et *easy-fix* sont délibérément laissés ouverts aux nouveaux contributeurs. Recherchez *help-wanted* et *good-first-issue* pour

## Rapports de bogues et demandes de fonctionnalités
### Sécurité
**DO NOT** publier les vulnérabilités de sécurité ou les exploits possibles sur toutes les plateformes, y compris l'onglet problèmes de ce référentiel. Au lieu de cela, envoyez-nous un [email](mailto:box@cyberhack.fr), afin que nous puissions y jeter un œil.
Il est possible que les instances accessibles à distance de ce logiciel soient affectées par vos découvertes !

### Bugs généraux et demandes de fonctionnalités
Toutes les autres formes de conclusions et de demandes sont les bienvenues pour être publiées et discutées publiquement sur l'onglet problèmes de ce référentiel.

# Licence
Comme introduit dans la section contribution, la CBox est sous licence [AGPL-3.0](LICENSE) ([TL;DR](https://tldrlegal.com/license/gnu-affero-general-public-license-v3-(agpl-3.0))).