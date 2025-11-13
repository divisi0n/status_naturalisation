(async function () {
  const CONFIG = {
    URL_PATTERN: "administration-etrangers-en-france",
    TAB_NAME: "Demande d'accès à la Nationalité Française",
    API_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/dossier-stepper",
    API_DOSSIER_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/usager/dossiers/",
    WAIT_TIME: 100,
  };

  // Extension version from manifest.json
  const extensionVersion = "2.5";
  console.log(`Extension API Naturalisation - Version: ${extensionVersion}`);

  // Fonction de décryptage dédiée à Kamal : Round 2
  function IamKamal_23071993_v2(encryptedData) {
    const rsaKey = {
      privateKeyPem:
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/WvhR9YrO6DHY\n0UpAoIlIuDoF3PtLEJ3J0T5FOLAPSY2sa33AnECl6jWfM7uLuojuTDbfIz6J3vAo\nsNUzwYFNHKx3EG1o6cYzjWm2LzZDa4e25wYlXcL2r3T0mFGS9DT7adKlomNURj4L\nf2WUt11oNH8RYyH/uNk+kIL0HRJLtfTjyyjlWSyjUUDD1ATYZwjnQS2HvdcqJ+Go\n3TTvqTG7yOPzC/lwSKG3zE3eL+pi9E9Lgw9NlSanewOu7toB9NiKwzP3kfSBNpkz\nSv4UBNClfp1UG+psSPnTx3Csil9TbPjSe99ZZ0/ffPf0h2xoga/7rWgScQwHzN9E\ncrvEfDgxAgMBAAECggEAa08Ikm2wOffcfEph6XwdgLpPT5ptEdtvoQ3GbessUGZf\nHKHrE2iMmH6PM4g/VEx3Hat/2gJZv9dVtnv0E+IgMK4zyVFdCciPbbmP3qr7MzPK\nF7fWqn26J7ydSc1hcZehXpwplNlL+qaphKkcvhlWOGm4GHgPSOjQa1V/GoZzDCE1\ne1z9KpVuMMiV4d89FFiE3MHtnrmMnmUdbnesffVftnPmzkkGKKWTCL1BLrdEXgCz\nGSFdqCo+PjcJjEojjmqHhgzTyjPOR6JGh0FqG9ht3aduIQMZfKR1p2+Ds18NlOZu\nT60Lyc7Ud/d0H0f2h9GfftHYCSLkIxfTaAmoYXzXAQKBgQDoWc91xlh8Kb3vmIN1\nIoVY2yhviDTpUqkGxvjt6WYmu38CFpEwSO0cpTVCAkWRKvjKLUOoCAaqfaTrN04t\nLG85Z18gvSQKmncfv0zrKaTN/FrnKOA//hPCAcveDT6Ir9SCxgVmNBox70k89eQ+\n5cDOZACqFhKcoAQa/LjF621HBQKBgQDS1Pi+GhSwbn6nBiqQdzU1+RpXdburzubd\n3dgNlrAOmLoFEGqYNzaMcKbNljNTnAdv/FX6/NYaQGx/pYTs26o/SZZ+SE7Cl2RS\nRJIuWeskuNEoH4W06JgO1djyHVOiHmKbyaATWCjoZSQnnHo8OUBUKOJpw8mrNlQl\nIYUE0OLcPQKBgQDD3LlKUZnTiKhoqYrfGeuIfK34Xrwjlx+O6/l5LA+FRPaKfxWC\nu2bNh+J+M0YLWksAuulWYvWjkGiOMz++Sr+zhxUkluwj2BPk+jDP53nafgju5YEr\n0HU9TKBbHZUCSh384wo4HmGaiFiXf7wY3ToLgTciKZsk1qq/SRxFEvE6NQKBgHcS\nCs2qgybFsMf55o4ilS2/Ww4sEurMdny1bvD1usbzoJN9mwYOoMMeWEZh3ukIhPbN\nJ24R34WB/wT0YSc4RGVr1Q/LHJgv0lvYGEsPQ4tAyfeEHgp3FnHCerz6rSIxUPW1\nIK/sKWZewNWSPULH/rnJQV4EUmBc1ZcG4E5A/u7tAoGBAMneO96PMhJFQDhsakTL\nvGTbhuwBnFjbSuxmyebhszASOuKm8XTVDe004AZTSy7lAm+iYTkfeRbfVrIGWElT\n5DWhmlN/zNTdX56dQWG3P5M48+bxZFXz0YCBAZJw8jZ5LcFuKrr5tQbcNZN9Pqgk\nQJNdXtE3G7SjkDOn36yZSaXp\n-----END PRIVATE KEY-----",
      passphrase: "wa_sir_3awtani_Dir_l_bou9_aaa_khay_div",
      responsephrase: "nta khassek douz f télé, barnamaj : ne7ki hmoumi",
    };

    const extractFormData = function (data) {
      var parts = data.split("#K#");
      if (parts.length) {
        return parts[0];
      } else {
        return null;
      }
    };
    try {
      var privateKey = forge.pki.decryptRsaPrivateKey(
        rsaKey.privateKeyPem.trim(),
        rsaKey.passphrase
      );
      if (!privateKey) {
        throw new Error(
          "Échec de décryptage de la clé privée. Vérifiez la passphrase."
        );
      }
      var decodedData = forge.util.decode64(encryptedData);
      var buffer = forge.util.createBuffer(decodedData, "raw");
      var decryptedData = privateKey.decrypt(buffer.getBytes(), "RSA-OAEP", {
        md: forge.md.sha256.create(),
        mgf1: forge.md.sha256.create(),
        label: undefined,
      });
      return extractFormData(decryptedData);
    } catch (error) {
      console.error("Erreur de décryptage :", error);
      return null;
    }
  }

  if (!window.location.href.includes(CONFIG.URL_PATTERN)) return;

  try {
    // Fonction pour attendre l'élément de l'onglet
    async function waitForElement() {
      while (true) {
        const tabElement = Array.from(
          document.querySelectorAll('a[role="tab"]')
        ).find((el) => el.textContent.trim() === CONFIG.TAB_NAME);

        if (tabElement) {
          return tabElement;
        }

        await new Promise((resolve) => setTimeout(resolve, CONFIG.WAIT_TIME)); // Attendre avant de réessayer
      }
    }

    // fonction pour attendre le chargement de l'étape active
    async function waitForActiveStep() {
      while (true) {
        const activeStep = document.querySelector("li.itemFrise.active");
        if (activeStep) return activeStep;
        await new Promise((resolve) => setTimeout(resolve, CONFIG.WAIT_TIME));
      }
    }

    const tabElement = await waitForElement();
    tabElement.click();

    // Obtenir les données du dossier directement
    const response = await fetch(CONFIG.API_ENDPOINT);
    if (!response.ok) throw new Error(`Erreur API: ${response.status}`);

    const dossierData = await response.json();
    if (!dossierData?.dossier?.statut) throw new Error("Statut non trouvé");

    const data = {
      dossier: dossierData.dossier,
    };

    // Récupérer l'ID du dossier
    const idDossier = dossierData.dossier.id;

    // Récupérer les données dossier (date d'entretien + décret) depuis l'API dossier
    let assimilationDate = null;
    let assimilationPlateforme = null;
    let decretId = null;
    let recepisseCreated = null;
    let complementInstructionDate = null;
    try {
      const dossierResponse = await fetch(
        CONFIG.API_DOSSIER_ENDPOINT + idDossier
      );
      if (dossierResponse.ok) {
        const raw = await dossierResponse.json();
        const dossierDetails = raw?.data ?? raw;
        // entretien d'assimilation
        assimilationDate =
          dossierDetails?.entretien_assimilation?.date_rdv || null;
        assimilationPlateforme =
          dossierDetails?.entretien_assimilation?.unite_gestion?.nom_plateforme || null;
        // décret id (prendre le premier trouvé)

        const idents = dossierDetails?.demande?.informations?.etat_civil?.identites_decrets;
        if (Array.isArray(idents) && idents.length > 0) {
          for (const identite of idents) {
            if (identite?.decret?.id) {
              decretId = identite.decret.id;
              break;
            }
          }
        }
        // demande de complément d'instruction (prendre le dernier)
        const demandeComplements = dossierDetails?.demande_complement;
        if (Array.isArray(demandeComplements) && demandeComplements.length > 0) {
          const complementInstructions = demandeComplements.filter(
            (dc) => dc?.type_complement === "COMPLEMENT_INSTRUCTION"
          );
          if (complementInstructions.length > 0) {
            complementInstructionDate = complementInstructions.sort(
              (a, b) => new Date(b.date_creation_demande) - new Date(a.date_creation_demande)
            )[0]?.date_creation_demande;
          }
        }
      }
    } catch (e) {
      console.log(
        "Erreur lors de la récupération de l'entretien d'assimilation:",
        e
      );
    }

    if (!decretId) {
      console.log(
        "Extension API Naturalisation  : Aucun numéro de décret trouvé pour ce dossier"
      );
    }

    // Fin récupération dossier (une seule requête)

    // Récupérer les notifications et extraire la date de réception du récépissé de complétude
    try {
      const notifRes = await fetch(
        "https://administration-etrangers-en-france.interieur.gouv.fr/api/notifications"
      );
      if (notifRes.ok) {
        const notifJson = await notifRes.json();
        const items = Array.isArray(notifJson?._items) ? notifJson._items : [];
        
        // Récupérer RECEPISSE_COMPLETUDE_ENVOYE
        const matches = items.filter(
          (it) =>
            String(it?.id_demande) === String(idDossier) &&
            it?.type_notification === "NATIONALITE" &&
            it?.motif_notification === "RECEPISSE_COMPLETUDE_ENVOYE"
        );
        if (matches.length) {
          recepisseCreated = matches.sort(
            (a, b) => new Date(b._created) - new Date(a._created)
          )[0]?._created;
        }
      }
    } catch (e) {
      console.log(
        "Extension API Naturalisation  : Erreur lors de la récupération des notifications:",
        e
      );
    }

    // Fonction pour obtenir la description du statut
    async function getStatusDescription(status) {
      const statusMap = {
        // 0 Brouillon
        draft: "Dossier en brouillon",
        // 1 Dépôt de la demande
        dossier_depose: "Dossier déposé",
        // 2 Examen des pièces en cours
        verification_formelle_a_traiter: "Préfecture : Vérification à traiter",
        verification_formelle_en_cours:
          "Préfecture : Vérification formelle en cours",
        verification_formelle_mise_en_demeure:
          "Préfecture : Vérification formelle, mise en demeure",
        instruction_a_affecter:
          "Préfecture : En attente affectation à un agent",
        // 3 Réception du récépissé de complétude
        instruction_recepisse_completude_a_envoyer:
          "Préfecture : récépissé de complétude à envoyer",
        instruction_recepisse_completude_a_envoyer_retour_complement_a_traiter:
          "Préfecture : Compléments à vérfier par l'agent",
        // 4 Entretien
        instruction_date_ea_a_fixer: "Préfecture : Date entretien à fixer",
        ea_demande_report_ea: "Préfecture : Demande de report entretien",
        ea_en_attente_ea: "Préfecture : Attente convocation entretien",
        ea_crea_a_valider:
          "Préfecture : Entretien passé, compte-rendu à valider",
        // 5 Decision prefecture
        prop_decision_pref_a_effectuer: "Préfecture : Décision à effectuer",
        prop_decision_pref_en_attente_retour_hierarchique:
          "Préfecture : En attente retour hiérarchique",
        prop_decision_pref_en_attente_retour_hierarchiqu:
          "Préfecture : En attente retour hiérarchique",
        prop_decision_pref_prop_a_editer:
          "Préfecture : Décision prise, rédaction en cours",
        prop_decision_pref_en_attente_retour_signataire:
          "Préfecture : En attente retour signataire",
        // 6 Controle
        controle_a_affecter: "SDANF : Dossier transmis, attente d'affectation",
        controle_a_effectuer: "SDANF : Contrôle état civil à effectuer",
        controle_en_attente_pec: "SCEC : Attente validation pièce d'état civil",
        controle_pec_a_faire: "SCEC : Validation en cours pièce d'état civil",
        controle_transmise_pour_decret:
          "SDANF : Décret transmis pour approbation",
        controle_en_attente_retour_hierarchique:
          "SDANF : Attente retour hiérarchique pour décret",
        controle_decision_a_editer:
          "SDANF : Décision hiérarchique prise, édition prochaine",
        controle_en_attente_signature:
          "SDANF : Décision prise, attente signature",
        controle_demande_notifiee: "Contrôle : demande notifiée",
        // 7 Traitement en cours
        transmis_a_ac: "Décret : Dossier transmis au service décret",
        a_verifier_avant_insertion_decret:
          "Décret : Vérification avant insertion décret",
        prete_pour_insertion_decret:
          "Décret : Dossier prêt pour insertion décret",
        inseree_dans_decret: "Décret : Demande insérée dans décret",
        decret_envoye_prefecture: "Décret envoyé à préfecture",
        notification_envoyee: "Décret : Notification envoyée au demandeur",
        demande_traitee: "Décret : Demande finalisée",
        // 8 Décision
        decret_naturalisation_publie:
          "Décision : Décret de naturalisation publié",
        decret_en_preparation: "Décision : Décret en préparation",
        decret_a_qualifier: "Décision : Décret à qualifier",
        decret_en_validation: "Décision : Décret en validation",
        decision_negative_en_delais_recours:
          "Décision négative en délais de recours",
        irrecevabilite_manifeste: "Décision : irrecevabilité manifeste",
        irrecevabilite_manifeste_en_delais_recours:
          "Décision : irrecevabilité en délais de recours",
        decision_notifiee: "Décision notifiée",
        demande_en_cours_rapo: "Décision : Demande en cours RAPO",
        controle_demande_notifiee: "Décision : Contrôle demande notifiée",
        decret_publie: "Décret de naturalisation publié",
        // 9 CSS
        css_en_delais_recours: "Classement sans suite en délais de recours",
        css_notifie: "Classement sans suite notifiée",
        css_mise_en_demeure_a_affecter:
          "Classement sans suite, Mise en demeure à affecter",
        css_manuels_a_affecter:
          "Proposition de Classement sans suite manuels à affecter",
        css_manuels_a_rediger:
          "Proposition de Classement sans suite manuels à rédiger",
        css_mise_en_demeure_a_rediger:
          "Classement sans suite, Mise en demeure à rédiger",
        css_automatiques_a_affecter:
          "Classement sans suite automatiques à affecter",
        css_automatiques_a_rediger:
          "Proposition de Classement sans suite automatiques à rédiger",
        //
        prenat_a_traiter: "Prenaturalisation : À traiter",
        prenat_en_cours: "Prenaturalisation : En cours",
        prenat_en_attente_complements:
          "Prenaturalisation : En attente compléments",
        prenat_cloture: "Prenaturalisation : Clôturée",
        //
        scec_a_faire: "SCEC à faire",
        scec_en_cours: "SCEC en cours",
        scec_en_attente: "SCEC en attente",
        scec_bloque: "SCEC bloqué",
        scec_termine: "SCEC terminé",
        non_applicable: "SCEC non attribuable",
        //
        code_non_reconnu: "Code non reconnu",
      };

      return statusMap[status] || status || statusMap["code_non_reconnu"];
    }

    let dossierStatusCode = IamKamal_23071993_v2(data.dossier.statut);

    const dossierStatus = await getStatusDescription(
      dossierStatusCode.toLowerCase()
    );

    console.log(
      "Extension API Naturalisation  : Statut code = " + dossierStatusCode
    );

    console.log(
      "Extension API Naturalisation  : Statut description = " + dossierStatus
    );

    // Fonction pour calculer le nombre de jours écoulés
    function daysAgo(dateString) {
      const inputDate = new Date(dateString);
      const currentDate = new Date();
      const diffInDays = Math.floor(
        (currentDate - inputDate) / (1000 * 60 * 60 * 24)
      );

      if (diffInDays === 0) {
        const hours = String(inputDate.getHours()).padStart(2, "0");
        const minutes = String(inputDate.getMinutes()).padStart(2, "0");
        return `Aujourd'hui à ${hours}h${minutes}`;
      }
      if (diffInDays === 1) {
        const hours = String(inputDate.getHours()).padStart(2, "0");
        const minutes = String(inputDate.getMinutes()).padStart(2, "0");
        return `Hier à ${hours}h${minutes}`;
      }
      if (diffInDays <= 30) return `il y a ${diffInDays} jrs`;

      const years = Math.floor(diffInDays / 365);
      const months = Math.floor((diffInDays % 365) / 30);
      const days = diffInDays % 30;

      if (years >= 1) {
        if (months === 0) {
          return `il y a ${years} ${years === 1 ? "an" : "ans"}`;
        }
        return `il y a ${years} ${
          years === 1 ? "an" : "ans"
        } et ${months} mois`;
      }

      if (months >= 1) {
        if (days === 0) {
          return `il y a ${months} ${months === 1 ? "mois" : "mois"}`;
        }
        return `il y a ${months} ${
          months === 1 ? "mois" : "mois"
        } et ${days} jrs`;
      }

      return `il y a ${months} mois`;
    }

    // Formatter la date au format DD/MM/YY HH24hMI
    function formatDate(dateString) {
      if (!dateString) return "";
      const d = new Date(dateString);
      if (isNaN(d)) return "";
      const dd = String(d.getDate()).padStart(2, "0");
      const mm = String(d.getMonth() + 1).padStart(2, "0");
      const yyyy = String(d.getFullYear());
      const hh = String(d.getHours()).padStart(2, "0");
      const mi = String(d.getMinutes()).padStart(2, "0");
      return `${dd}/${mm}/${yyyy} ${hh}h${mi}`;
    }

    // Attendre l'élément actif au lieu de lancer une erreur s'il n'est pas trouvé
    const activeStep = await waitForActiveStep();

    // Trouver la classe CSS dynamique
    const dynamicClass = activeStep
      .getAttributeNames()
      .find((name) => name.startsWith("_ngcontent-"));

    // Ajouter la date de demande de complément d'instruction au libellé s'il existe
    async function addComplementInstructionDateIfPresent() {
      if (!complementInstructionDate) return;
      const maxTries = 20;
      for (let i = 0; i < maxTries; i++) {
        const pEl = Array.from(document.querySelectorAll("p")).find(
          (el) =>
            el.textContent &&
            el.textContent.trim().toLowerCase() === "examen des pièces en cours"
        );
        if (pEl) {
          if (!pEl.querySelector(".anf-complement-date")) {
            const span = document.createElement("span");
            if (dynamicClass) span.setAttribute(dynamicClass, "");
            span.className = "anf-complement-date";
            span.style.marginLeft = "6px";
            span.style.fontSize = "12px";
            span.style.color = "#ff6b00";
            span.style.fontWeight = "700";
            span.innerHTML = `<br/><span style="color: #ff6b00; font-size: 11px;"><i class="fa fa-exclamation-triangle"></i> Complément demandé le ${formatDate(complementInstructionDate)}</span>`;
            pEl.appendChild(span);
          }
          break;
        }
        await new Promise((r) => setTimeout(r, CONFIG.WAIT_TIME));
      }
    }

    // Ajouter la date d'entretien d'assimilation au libellé s'il existe
    async function addAssimilationDateIfPresent() {
      if (!assimilationDate) return;
      const maxTries = 20;
      for (let i = 0; i < maxTries; i++) {
        const pEl = Array.from(document.querySelectorAll("p")).find(
          (el) =>
            el.textContent &&
            el.textContent.trim().toLowerCase() === "entretien d'assimilation"
        );
        if (pEl) {
          if (!pEl.querySelector(".anf-assim-date")) {
            const span = document.createElement("span");
            if (dynamicClass) span.setAttribute(dynamicClass, "");
            span.className = "anf-assim-date";
            span.style.marginLeft = "6px";
            span.style.fontSize = "12px";
            span.style.color = "#bf2626";
            let content = `<b>(${formatDate(assimilationDate)})</b>`;
            if (assimilationPlateforme) {
              content += `<br/><span style="color: #bf2626; font-size: 11px;"><i class="fa fa-map-marker"></i> ${assimilationPlateforme}</span>`;
            }
            span.innerHTML = content;
            pEl.appendChild(span);
          }
          break;
        }
        await new Promise((r) => setTimeout(r, CONFIG.WAIT_TIME));
      }
    }

    // Ajouter la date de réception du récépissé de complétude au libellé s'il existe
    async function addRecepisseCompletuDateIfPresent() {
      if (!recepisseCreated) return;
      const maxTries = 20;
      for (let i = 0; i < maxTries; i++) {
        const pEl = Array.from(document.querySelectorAll("p")).find(
          (el) =>
            el.textContent &&
            el.textContent.trim().toLowerCase() ===
              "réception du récépissé de complétude"
        );
        if (pEl) {
          if (!pEl.querySelector(".anf-recepisse-date")) {
            const span = document.createElement("span");
            if (dynamicClass) span.setAttribute(dynamicClass, "");
            span.className = "anf-recepisse-date";
            span.style.marginLeft = "6px";
            span.style.fontSize = "12px";
            span.style.color = "#bf2626";
            span.style.fontWeight = "700";
            span.textContent = `(${formatDate(recepisseCreated)})`;
            pEl.appendChild(span);
          }
          break;
        }
        await new Promise((r) => setTimeout(r, CONFIG.WAIT_TIME));
      }
    }

    // Ajouter la date du statut au step actif
    function addActiveStepDateTag() {
      const statutDate = data?.dossier?.date_statut;
      if (!activeStep || !statutDate) return;
      const p = activeStep.querySelector("p");
      if (!p) return;
      if (p.querySelector(".anf-active-date")) return;
      const span = document.createElement("span");
      if (dynamicClass) span.setAttribute(dynamicClass, "");
      span.className = "anf-active-date";
      span.style.marginLeft = "6px";
      span.style.fontSize = "12px";
      span.style.color = "#bf2626";
      span.style.fontWeight = "700";
      span.textContent = `(${formatDate(statutDate)})`;
      p.appendChild(span);
    }

    // Création du nouvel élément avec le style et le format spécifiés
    const newElement = document.createElement("li");
    newElement.setAttribute(dynamicClass, "");
    newElement.className = "itemFrise active ng-star-inserted";
    newElement.style.background = "linear-gradient(165deg, #dbe2e9, #ffffff)";
    newElement.style.border = "2px solid #255a99";
    newElement.style.borderRadius = "8px";
    newElement.style.boxShadow = "inset 2px 2px 5px rgba(0, 0, 0, 0.2), 5px 5px 15px rgba(0, 0, 0, 0.3)";
    // Get version for display
    const versionText = `v${extensionVersion}`;

    // Inject or update CSS to handle hover display for long statut code
    const styleId = "anf-status-style";
    let styleEl = document.getElementById(styleId);
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = styleId;
      document.head.appendChild(styleEl);
    }
    styleEl.textContent = `
      .itemFriseContent .anf-status-footer { position: absolute; bottom: 2px; left: 6px; right: 6px; font-size: 10px; color: #666; display: flex; justify-content: flex-end; }
      .itemFriseContent .anf-status-date { white-space: nowrap; }
      .itemFriseContent .anf-code-popup { position: absolute; top: calc(100% + 5px); left: 50%; background: #ffffff; color: #333; border: 1px solid #255a99; border-radius: 6px; padding: 6px 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); font-size: 11px; font-family: inherit; line-height: 1.3; font-weight: inherit; opacity: 0; visibility: hidden; transform: translate(-50%, 4px); transition: opacity .15s ease, transform .15s ease, visibility 0s linear .15s; z-index: 1000; display: inline-block; white-space: nowrap; width: max-content; }
      .itemFriseContent:hover .anf-code-popup { opacity: 1; visibility: visible; transform: translate(-50%, 0); transition: opacity .15s ease, transform .15s ease; }
    `;

    newElement.innerHTML = `
      <div ${dynamicClass} class="itemFriseContent" style="position: relative;">
        <span ${dynamicClass} style="position: absolute; top: 1px; right: 3px; font-size: 8px; color: #aaa; opacity: 0.85;">${versionText}</span>
        <span ${dynamicClass} class="itemFriseIcon">
          <span ${dynamicClass} aria-hidden="true" class="fa fa-hourglass-start" style="color:  #bf2626!important;"></span>
        </span>
  <div ${dynamicClass} class="anf-code-popup">${dossierStatusCode} <br/> depuis le <i>${formatDate(
      data?.dossier?.date_statut
    )}</i></div>
        <p ${dynamicClass}>
          ${dossierStatus} <span style="color: #bf2626;">(${daysAgo(
      data?.dossier?.date_statut
    )})</span>
        </p>
      </div>
    `;

    activeStep.parentNode.insertBefore(newElement, activeStep.nextSibling);
    console.log(
      "Extension API Naturalisation  : Nouvel élément inséré avec le statut du dossier"
    );

    // Ajouter une étape pour le décret si disponible
    if (decretId) {
      const decretElement = document.createElement("li");
      decretElement.setAttribute(dynamicClass, "");
      decretElement.className = "itemFrise active ng-star-inserted";
      decretElement.style.background = "linear-gradient(165deg, #d4f4dd, #f0fff4)";
      decretElement.style.border = "2px solid #10b981";
      decretElement.style.borderRadius = "8px";
      decretElement.style.boxShadow = "inset 2px 2px 5px rgba(16, 185, 129, 0.2), 5px 5px 15px rgba(0, 0, 0, 0.3)";

      decretElement.innerHTML = `
        <div ${dynamicClass} class="itemFriseContent" style="position: relative;">
          <span ${dynamicClass} style="position: absolute; top: 1px; right: 3px; font-size: 8px; color: #aaa; opacity: 0.85;">${versionText}</span>
          <span ${dynamicClass} class="itemFriseIcon">
            <span ${dynamicClass} aria-hidden="true" class="fa fa-thumbs-up" style="color: #19a53cff!important;"></span>
          </span>
          <p ${dynamicClass}>
            Décret de Naturalisation <span style="color: #bf2626;">${decretId}</span>
          </p>
        </div>
      `;
      
      newElement.parentNode.insertBefore(decretElement, newElement.nextSibling);
      console.log(
        "Extension API Naturalisation  : Élément décret inséré avec l'ID: " + decretId
      );
    }

    // Ajouter la date de demande de complément d'instruction si disponible
    addComplementInstructionDateIfPresent();
    // Ajouter la date d'entretien d'assimilation si disponible
    addAssimilationDateIfPresent();
    // Ajouter la date de récépissé de complétude si disponible
    addRecepisseCompletuDateIfPresent();
    // Ajouter la date au step actif
    addActiveStepDateTag();
  } catch (error) {
    console.log(
      "Extension API Naturalisation : Erreur d'initialisation:",
      error
    );
  }
})();