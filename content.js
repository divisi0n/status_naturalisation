(async function () {
  const CONFIG = {
    URL_PATTERN: "administration-etrangers-en-france",
    TAB_NAME: "Demande d'accès à la Nationalité Française",
    API_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/dossier-stepper",
    API_DOSSIER_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/usager/dossiers/",
    WAIT_TIME: 100,
    AUTH_WAIT_TIMEOUT: 15000,
    SSO_AUTH_WAIT_TIMEOUT: 90000,
  };

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function isOAuthCallback() {
    const href = window.location.href;
    return /(?:^|[?#&])code=/.test(href) && /session_state=/.test(href);
  }

  function isLoginPromptVisible() {
    return Boolean(
      document.querySelector('edu-item-link[data-item="Se connecter"]') ||
        document.querySelector('edu-item-link[data-item="Sign in"]')
    );
  }

  function isUserLoggedIn() {
    return Boolean(
      document.querySelector(
        'edu-item-link a.fr-icon-user-line[href*="mon-compte"], edu-item-link a[href*="/espace-personnel/mon-compte"]'
      )
    );
  }

  function getAuthState() {
    if (isUserLoggedIn()) return "logged-in";
    if (isLoginPromptVisible()) return "logged-out";
    return "unknown";
  }

  async function waitForAuthResolved() {
    const timeoutMs = isOAuthCallback()
      ? CONFIG.SSO_AUTH_WAIT_TIMEOUT
      : CONFIG.AUTH_WAIT_TIMEOUT;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const state = getAuthState();
      if (state !== "unknown") return state;
      await sleep(300);
    }

    return getAuthState();
  }

  async function fetchStepperOnce() {
    try {
      const response = await fetch(CONFIG.API_ENDPOINT, {
        credentials: "include",
      });

      if (response.status === 404 || response.status === 204) {
        return null;
      }

      if (!response.ok) {
        if (response.status === 401) {
          console.log(
            "Warning: Extension API Naturalisation — API stepper 401, session expirée"
          );
        }
        return null;
      }

      return response;
    } catch (error) {
      console.log(
        "Warning: Extension API Naturalisation — API stepper inaccessible:",
        error
      );
      return null;
    }
  }

  // Extension version from manifest.json
  const extensionVersion = "3.6.1";
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
      console.log("Error: Erreur de décryptage :", error);
      return null;
    }
  }

  if (!window.location.href.includes(CONFIG.URL_PATTERN)) return;

  function getStatusDescription(status) {
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

  function formatDate(dateString) {
    if (!dateString) return "";
    const d = new Date(dateString);
    if (isNaN(d)) return "";
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = String(d.getFullYear());
    return `${dd}/${mm}/${yyyy}`;
  }

  function parseAnchorDate(dateString) {
    if (!dateString) return null;
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return null;
    d.setHours(0, 0, 0, 0);
    return d;
  }

  function formatDurationBetween(startDate, endDate) {
    if (!startDate || !endDate) return null;
    const diffDays = Math.floor((endDate.getTime() - startDate.getTime()) / 86400000);
    if (diffDays < 0) return null;
    if (diffDays === 0) return "0 jrs";

    if (diffDays < 30) {
      return `${diffDays} jrs`;
    }

    const months = Math.floor(diffDays / 30);
    const days = diffDays % 30;

    if (months >= 1 && days > 0) {
      return `${months} mois et ${days} jrs`;
    }
    if (months >= 1) {
      return `${months} mois`;
    }
    return `${diffDays} jrs`;
  }

  function pickFirstRawDate(...values) {
    for (const value of values) {
      if (parseAnchorDate(value)) return value;
    }
    return null;
  }

  function pickLatestRawDate(...values) {
    let latest = null;
    let latestTime = -Infinity;
    for (const value of values) {
      const parsed = parseAnchorDate(value);
      if (!parsed) continue;
      const time = parsed.getTime();
      if (time > latestTime) {
        latestTime = time;
        latest = value;
      }
    }
    return latest;
  }

  function extractComplementDates(demandeComplements) {
    const result = { instructionDate: null, depotDate: null };
    if (!Array.isArray(demandeComplements) || !demandeComplements.length) {
      return result;
    }

    const instructions = demandeComplements.filter(
      (entry) => entry?.type_complement === "COMPLEMENT_INSTRUCTION"
    );
    if (!instructions.length) return result;

    const latestInstruction = [...instructions].sort(
      (a, b) =>
        new Date(b.date_creation_demande) - new Date(a.date_creation_demande)
    )[0];
    result.instructionDate = latestInstruction.date_creation_demande || null;

    const depotDates = [];
    for (const entry of demandeComplements) {
      for (const key of [
        "date_reponse_usager",
        "date_depot_complement",
        "date_complement_depot",
        "date_reponse",
        "date_validation",
        "date_fin_traitement",
        "date_modification",
      ]) {
        if (entry?.[key]) depotDates.push(entry[key]);
      }
    }

    result.depotDate = pickLatestRawDate(...depotDates);
    return result;
  }

  function resolveDemandeDeposeeRawDate(apiInfos, index, currentIndex) {
    const {
      demandeDate,
      complementInstructionDate,
      complementDepotDate,
      dossierDepotDate,
      dateStatut,
    } = apiInfos;
    const complementDate = parseAnchorDate(complementInstructionDate);

    if (complementDate) {
      const candidates = [complementDepotDate, dossierDepotDate];
      const demandeParsed = parseAnchorDate(demandeDate);
      if (demandeParsed && demandeParsed.getTime() >= complementDate.getTime()) {
        candidates.push(demandeDate);
      }
      if (index === currentIndex) {
        candidates.push(dateStatut);
      }
      return pickLatestRawDate(...candidates);
    }

    return pickFirstRawDate(
      dossierDepotDate,
      demandeDate,
      index === currentIndex ? dateStatut : null
    );
  }

  function getStepAnchorRawDate(stepKey, index, currentIndex, apiInfos) {
    const {
      demandeDate,
      complementInstructionDate,
      recepisseCreated,
      assimilationDate,
      dateStatut,
      decretDate,
      decretId,
    } = apiInfos;

    switch (stepKey) {
      case "demande_envoyee":
        return demandeDate;
      case "examen_pieces":
        return (
          complementInstructionDate ||
          (index <= currentIndex ? dateStatut : null)
        );
      case "demande_deposee":
        return resolveDemandeDeposeeRawDate(apiInfos, index, currentIndex);
      case "recepisse_completude":
        return recepisseCreated;
      case "entretien_assimilation":
        return assimilationDate;
      case "decision_prise":
        return decretDate || (decretId && index === currentIndex ? dateStatut : null);
      case "ceremonie_naturalisation":
        return index === currentIndex ? dateStatut : null;
      default:
        return index === currentIndex ? dateStatut : null;
    }
  }

  function getStepKnownDate(stepKey, index, currentIndex, apiInfos) {
    return parseAnchorDate(
      getStepAnchorRawDate(stepKey, index, currentIndex, apiInfos)
    );
  }

  function getDurationBetweenSteps(fromStep, fromIndex, toStep, toIndex, currentIndex, apiInfos) {
    const fromDate = getStepKnownDate(fromStep.key, fromIndex, currentIndex, apiInfos);
    const toDate = getStepKnownDate(toStep.key, toIndex, currentIndex, apiInfos);
    return formatDurationBetween(fromDate, toDate);
  }

  function hasNaturalisationData(apiInfos) {
    if (!apiInfos?.idDossier || !apiInfos?.dossier?.statut) return false;

    const code = String(apiInfos.statutCode || "").trim();
    if (!code || code === "-" || code.toLowerCase() === "code_non_reconnu") {
      return false;
    }

    return Boolean(apiInfos.statutDescription);
  }

  function removeStepperIfPresent() {
    document.getElementById("anf-extension-stepper-root")?.remove();
  }

  async function fetchApiInfos() {
    const response = await fetchStepperOnce();
    if (!response) return null;

    let dossierData;
    try {
      dossierData = await response.json();
    } catch {
      return null;
    }

    if (!dossierData?.dossier?.id || !dossierData?.dossier?.statut) {
      return null;
    }

    const data = { dossier: dossierData.dossier };
    const idDossier = dossierData.dossier.id;
    const dossierStatusCode = IamKamal_23071993_v2(data.dossier.statut);
    if (
      !dossierStatusCode ||
      dossierStatusCode === "-" ||
      String(dossierStatusCode).trim() === ""
    ) {
      return null;
    }

    const dossierStatus = getStatusDescription(
      String(dossierStatusCode).toLowerCase()
    );

    return {
      version: extensionVersion,
      idDossier,
      statutCode: dossierStatusCode,
      statutDescription: dossierStatus,
      dateStatut: data.dossier.date_statut,
      dateStatutRelative: daysAgo(data.dossier.date_statut),
      demandeDate: null,
      complementInstructionDate: null,
      complementDepotDate: null,
      dossierDepotDate: null,
      assimilationDate: null,
      assimilationPlateforme: null,
      recepisseCreated: null,
      decretId: null,
      decretDate: null,
      dossier: data.dossier,
      dossierDetails: null,
      notifications: [],
      raw: {
        stepper: dossierData,
        dossier: null,
        notifications: [],
      },
    };
  }

  async function enrichApiInfos(apiInfos) {
    const idDossier = apiInfos.idDossier;
    const [dossierRaw, notifRaw] = await Promise.all([
      fetch(CONFIG.API_DOSSIER_ENDPOINT + idDossier)
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
      fetch(
        "https://administration-etrangers-en-france.interieur.gouv.fr/api/notifications"
      )
        .then((res) => (res.ok ? res.json() : null))
        .catch(() => null),
    ]);

    if (dossierRaw) {
      const dossierDetails = dossierRaw?.data ?? dossierRaw;
      apiInfos.dossierDetails = dossierDetails;
      apiInfos.raw.dossier = dossierDetails;
      apiInfos.demandeDate =
        dossierDetails?.taxe_payee?.date_consommation || null;
      apiInfos.dossierDepotDate = pickFirstRawDate(
        dossierDetails?.date_depot,
        dossierDetails?.demande?.date_depot,
        dossierDetails?.demande?.date_validation,
        dossierDetails?.demande?.date_creation,
        dossierDetails?.date_validation,
        apiInfos.dossier?.date_depot
      );
      apiInfos.assimilationDate =
        dossierDetails?.entretien_assimilation?.date_rdv || null;
      apiInfos.assimilationPlateforme =
        dossierDetails?.entretien_assimilation?.unite_gestion?.nom_plateforme ||
        null;

      const idents =
        dossierDetails?.demande?.informations?.etat_civil?.identites_decrets;
      if (Array.isArray(idents) && idents.length > 0) {
        for (const identite of idents) {
          if (identite?.decret?.id) {
            apiInfos.decretId = identite.decret.id;
            apiInfos.decretDate =
              identite.decret.date_publication ||
              identite.decret.date_parution ||
              identite.decret.date_parution_jo ||
              identite.decret.date_signature ||
              identite.decret.date ||
              null;
            break;
          }
        }
      }

      const demandeComplements = dossierDetails?.demande_complement;
      const complementDates = extractComplementDates(demandeComplements);
      apiInfos.complementInstructionDate = complementDates.instructionDate;
      apiInfos.complementDepotDate = complementDates.depotDate;
    }

    if (notifRaw) {
      apiInfos.notifications = Array.isArray(notifRaw?._items)
        ? notifRaw._items
        : [];
      apiInfos.raw.notifications = apiInfos.notifications;
      const matches = apiInfos.notifications.filter(
        (it) =>
          String(it?.id_demande) === String(idDossier) &&
          it?.type_notification === "NATIONALITE" &&
          it?.motif_notification === "RECEPISSE_COMPLETUDE_ENVOYE"
      );
      if (matches.length) {
        apiInfos.recepisseCreated = matches.sort(
          (a, b) => new Date(b._created) - new Date(a._created)
        )[0]?._created;
      }

      if (apiInfos.complementInstructionDate && !apiInfos.complementDepotDate) {
        const complementDate = parseAnchorDate(apiInfos.complementInstructionDate);
        const depotCandidates = apiInfos.notifications
          .filter((item) => {
            if (String(item?.id_demande) !== String(idDossier) || !item?._created) {
              return false;
            }
            const created = parseAnchorDate(item._created);
            if (!created || !complementDate || created < complementDate) return false;
            const motif = String(item.motif_notification || "").toUpperCase();
            return /COMPLEMENT|DEPOT|DEPOSE|COMPLET|INSTRUCTION/.test(motif);
          })
          .map((item) => item._created)
          .sort((a, b) => new Date(a) - new Date(b));
        if (depotCandidates.length) {
          apiInfos.complementDepotDate = depotCandidates[0];
        }
      }
    }

    return apiInfos;
  }

  function logApiInfos(apiInfos) {
    window.__ANF_API_INFOS__ = apiInfos;

    console.group(
      `Extension API Naturalisation v${apiInfos.version} — Infos API`
    );
    console.log("Statut code:", apiInfos.statutCode);
    console.log("Statut description:", apiInfos.statutDescription);
    console.log("Date statut:", apiInfos.dateStatut, `(${apiInfos.dateStatutRelative})`);
    console.log("ID dossier:", apiInfos.idDossier);
    console.log("Date demande:", apiInfos.demandeDate || "—");
    console.log("Complément instruction:", apiInfos.complementInstructionDate || "—");
    console.log("Entretien assimilation:", apiInfos.assimilationDate || "—");
    if (apiInfos.assimilationPlateforme) {
      console.log("Plateforme assimilation:", apiInfos.assimilationPlateforme);
    }
    console.log("Récépissé complétude:", apiInfos.recepisseCreated || "—");
    console.log("N° décret:", apiInfos.decretId || "—");
    console.log("Résumé:", {
      statutCode: apiInfos.statutCode,
      statutDescription: apiInfos.statutDescription,
      dateStatut: apiInfos.dateStatut,
      idDossier: apiInfos.idDossier,
      decretId: apiInfos.decretId,
    });
    console.log("Données brutes (stepper):", apiInfos.raw.stepper);
    console.log("Données brutes (dossier):", apiInfos.raw.dossier);
    console.log("Données brutes (notifications):", apiInfos.raw.notifications);
    console.log(
      "Accès rapide console: tapez __ANF_API_INFOS__ pour revoir toutes les infos"
    );
    console.groupEnd();
  }

  const RECREATED_TRACKING_STEPS = [
    { key: "demande_envoyee", title: "Demande envoyée" },
    { key: "examen_pieces", title: "Examen des pièces en cours" },
    { key: "demande_deposee", title: "Demande déposée" },
    { key: "traitement_plateforme_1", title: "Traitement en cours (Plateforme)" },
    { key: "recepisse_completude", title: "Réception du récépissé de complétude" },
    { key: "traitement_plateforme_2", title: "Traitement en cours (Plateforme)" },
    { key: "entretien_assimilation", title: "Entretien d'assimilation" },
    { key: "traitement_plateforme_3", title: "Traitement en cours (Plateforme)" },
    { key: "traitement_sdanf_1", title: "Traitement en cours (SDANF)" },
    { key: "traitement_scec", title: "Traitement en cours (SCEC)" },
    { key: "traitement_sdanf_2", title: "Traitement en cours (SDANF)" },
    { key: "decision_prise", title: "Décision prise" },
    { key: "ceremonie_naturalisation", title: "Cérémonie de naturalisation" },
  ];

  const MACRO_PHASES = [
    {
      key: "prefecture",
      title: "Préfecture",
      subtitle: "Dépôt, examen des pièces, entretien et instruction préfectorale",
      startIndex: 0,
      endIndex: 7,
    },
    {
      key: "sdanf_scec",
      title: "SDANF & SCEC",
      subtitle: "Contrôles SDANF, validation SCEC, décret et cérémonie",
      startIndex: 8,
      endIndex: 12,
    },
  ];

  const MACRO_STATUS_ICONS = {
    done: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="m8 12.5 2.5 2.5L16 9.5"></path></svg>`,
    pending: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 2h12"></path><path d="M6 22h12"></path><path d="M8 2v5a4 4 0 0 0 8 0V2"></path><path d="M8 22v-5a4 4 0 0 1 8 0v5"></path><path d="M12 11v2"></path></svg>`,
    current: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 2h12"></path><path d="M6 22h12"></path><path d="M8 2v5a4 4 0 0 0 8 0V2"></path><path d="M8 22v-5a4 4 0 0 1 8 0v5"></path><path d="M12 11v2"></path></svg>`,
  };

  function getMacroPhaseState(phase, currentIndex) {
    if (currentIndex > phase.endIndex) return "done";
    if (currentIndex >= phase.startIndex && currentIndex <= phase.endIndex) {
      return "current";
    }
    return "pending";
  }

  function getMacroProgressPct(currentIndex) {
    const prefectureEnd = MACRO_PHASES[0].endIndex + 1;
    const sdanfSteps = MACRO_PHASES[1].endIndex - MACRO_PHASES[1].startIndex + 1;
    if (currentIndex < MACRO_PHASES[1].startIndex) {
      return Math.round(((currentIndex + 1) / prefectureEnd) * 50);
    }
    const sdanfProgress = currentIndex - MACRO_PHASES[1].startIndex + 1;
    return 50 + Math.round((sdanfProgress / sdanfSteps) * 50);
  }

  function createMacroStatusIcon(state) {
    const icon = document.createElement("span");
    icon.className = `anf-macro-status-icon is-${state}`;
    icon.innerHTML = MACRO_STATUS_ICONS[state] || MACRO_STATUS_ICONS.pending;
    icon.setAttribute("aria-hidden", "true");
    return icon;
  }

  function getStepState(index, currentIndex) {
    if (index < currentIndex) return "done";
    if (index === currentIndex) return "current";
    return "pending";
  }

  function shouldShowStepInStepper(step, index, currentIndex) {
    return !(
      step.key.startsWith("traitement_plateforme") && index < currentIndex
    );
  }

  function buildTrackStepItem(step, index, currentIndex, apiInfos, railMeta = {}) {
    const {
      isFirst = false,
      isLast = false,
      lineInDone = false,
      lineOutDone = false,
      lineInDuration = null,
    } = railMeta;
    const state = getStepState(index, currentIndex);
    const item = document.createElement("div");
    item.className = `anf-track-step is-${state}`;
    item.setAttribute("role", "listitem");
    item.dataset.stepKey = step.key;

    const track = document.createElement("div");
    track.className = "anf-step-track";

    const lineIn = document.createElement("span");
    lineIn.className = "anf-step-line anf-step-line--in";
    if (lineInDone) lineIn.classList.add("is-done");
    if (isFirst) lineIn.classList.add("is-hidden");
    lineIn.setAttribute("aria-hidden", "true");

    const node = document.createElement("span");
    node.className = "anf-step-node";
    node.appendChild(createStepIcon(step.key));

    const lineOut = document.createElement("span");
    lineOut.className = "anf-step-line anf-step-line--out";
    if (lineOutDone) lineOut.classList.add("is-done");
    if (isLast) lineOut.classList.add("is-hidden");
    lineOut.setAttribute("aria-hidden", "true");

    track.append(lineIn, node, lineOut);

    if (lineInDuration) {
      track.setAttribute("title", `Durée : ${lineInDuration}`);
      const durationEl = document.createElement("span");
      durationEl.className = "anf-step-duration";
      if (lineInDone) durationEl.classList.add("is-done");
      durationEl.textContent = lineInDuration;
      track.appendChild(durationEl);
    }

    const copy = document.createElement("div");
    copy.className = "anf-step-copy";

    const title = document.createElement("p");
    title.className = "anf-track-step-title";
    title.textContent = step.title;
    copy.appendChild(title);

    item.appendChild(track);
    item.appendChild(copy);
    appendStepDetails(copy, step.key, index, currentIndex, apiInfos);

    return item;
  }

  function buildMacroPhaseBlock(phase, currentIndex, apiInfos) {
    const state = getMacroPhaseState(phase, currentIndex);
    const block = document.createElement("div");
    block.className = `anf-macro-block is-${state}`;
    block.setAttribute("role", "listitem");
    block.dataset.phaseKey = phase.key;

    const inner = document.createElement("div");
    inner.className = "anf-macro-block-inner";

    inner.appendChild(createMacroStatusIcon(state));

    const content = document.createElement("div");
    content.className = "anf-macro-content";

    const head = document.createElement("div");
    head.className = "anf-macro-head";
    head.innerHTML = `
      <h3 class="anf-macro-title">${phase.title}</h3>
      <span class="anf-macro-badge">${state === "done" ? "Terminé" : state === "current" ? "En cours" : "À venir"}</span>
    `;
    content.appendChild(head);

    const subtitle = document.createElement("p");
    subtitle.className = "anf-macro-subtitle";
    subtitle.textContent = phase.subtitle;
    content.appendChild(subtitle);

    const stepperWrap = document.createElement("div");
    stepperWrap.className = "anf-phase-stepper-wrap";

    const stepper = document.createElement("div");
    stepper.className = "anf-phase-stepper";
    stepper.setAttribute("role", "list");
    stepper.setAttribute("aria-label", `Étapes ${phase.title}`);

    const phaseSteps = RECREATED_TRACKING_STEPS.slice(
      phase.startIndex,
      phase.endIndex + 1
    );
    const visibleSteps = phaseSteps
      .map((step, offset) => ({ step, index: phase.startIndex + offset }))
      .filter(({ step, index }) =>
        shouldShowStepInStepper(step, index, currentIndex)
      );

    visibleSteps.forEach(({ step, index }, visibleOffset) => {
      const isFirst = visibleOffset === 0;
      const isLast = visibleOffset === visibleSteps.length - 1;
      const prev = !isFirst ? visibleSteps[visibleOffset - 1] : null;
      const lineInDuration = prev
        ? getDurationBetweenSteps(
            prev.step,
            prev.index,
            step,
            index,
            currentIndex,
            apiInfos
          )
        : null;

      stepper.appendChild(
        buildTrackStepItem(step, index, currentIndex, apiInfos, {
          isFirst,
          isLast,
          lineInDone: !isFirst && index <= currentIndex,
          lineOutDone: !isLast && index < currentIndex,
          lineInDuration,
        })
      );
    });
    stepperWrap.appendChild(stepper);
    content.appendChild(stepperWrap);

    inner.appendChild(content);
    block.appendChild(inner);
    return block;
  }

  function createStepIcon(stepKey) {
    const iconByStep = {
      demande_envoyee: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M22 2 11 13"></path><path d="m22 2-7 20-4-9-9-4 20-7Z"></path></svg>`,
      examen_pieces: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 0 1-9 9 8.7 8.7 0 0 1-6-2.4"></path><path d="M3 12a9 9 0 0 1 15-6.7"></path><path d="M18 3v5h-5"></path><path d="M6 21v-5h5"></path></svg>`,
      demande_deposee: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v1"></path><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7H3"></path></svg>`,
      traitement_plateforme_1: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      recepisse_completude: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"></path><path d="M14 2v6h6"></path><path d="M8 13h8"></path><path d="M8 17h6"></path></svg>`,
      traitement_plateforme_2: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      entretien_assimilation: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4Z"></path><path d="M8 9h8"></path><path d="M8 13h5"></path></svg>`,
      traitement_plateforme_3: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      traitement_sdanf_1: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      traitement_scec: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>`,
      traitement_sdanf_2: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      decision_prise: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2Z"></path><path d="m22 6-10 7L2 6"></path></svg>`,
      ceremonie_naturalisation: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"></rect><circle cx="8.5" cy="10" r="2"></circle><path d="M6 16c.7-1.4 1.5-2 2.5-2s1.8.6 2.5 2"></path><path d="M14 9h4"></path><path d="M14 13h4"></path><path d="M14 17h3"></path></svg>`,
    };

    const icon = document.createElement("span");
    icon.className = "anf-track-step-icon";
    icon.innerHTML = iconByStep[stepKey] || iconByStep.traitement_plateforme_1;
    return icon;
  }

  const VISIBILITY_ICON_SVG = {
    hidden: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.7 10.7a3 3 0 0 0 4.6 4.6"></path><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7"></path><path d="m2 2 20 20"></path></svg>`,
    visible: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7"></path><circle cx="12" cy="12" r="3"></circle></svg>`,
  };

  function createVisibilityToggleIcon(hidden) {
    const icon = document.createElement("span");
    icon.className = "anf-toggle-plateforme";
    icon.setAttribute("aria-hidden", "true");
    icon.innerHTML = hidden
      ? VISIBILITY_ICON_SVG.hidden
      : VISIBILITY_ICON_SVG.visible;
    return icon;
  }

  function inferRecreatedTrackingIndex(statusCode) {
    const code = String(statusCode || "").trim().toLowerCase();
    if (!code || code === "-" || code === "code_non_reconnu") return 0;
    if (code === "draft") return 0;
    if (code === "dossier_depose") return 2;
    if (code.startsWith("verification_")) return 1;
    if (code.startsWith("instruction_recepisse")) return 4;
    if (code === "instruction_date_ea_a_fixer") return 5;
    if (code.startsWith("ea_") || code.includes("date_ea")) return 6;
    if (code.startsWith("instruction_")) return 3;
    if (code.startsWith("prop_decision_pref_")) return 7;
    if (
      code === "controle_a_affecter" ||
      code === "controle_a_effectuer" ||
      code === "controle_en_attente_retour_ministeriel" ||
      code === "controle_en_attente_retour_prefecture"
    ) {
      return 8;
    }
    if (
      code === "controle_en_attente_pec" ||
      code === "controle_pec_a_faire" ||
      code.startsWith("scec_") ||
      code === "non_applicable"
    ) {
      return 9;
    }
    if (code.startsWith("controle_")) return 10;
    if (
      code.startsWith("decret_") ||
      code === "transmis_a_ac" ||
      code === "a_verifier_avant_insertion_decret" ||
      code === "prete_pour_insertion_decret" ||
      code === "inseree_dans_decret" ||
      code === "decret_envoye_prefecture" ||
      code === "notification_envoyee" ||
      code === "demande_traitee" ||
      code.startsWith("decision_") ||
      code.startsWith("css_") ||
      code.includes("irrecevabilite") ||
      code === "demande_en_cours_rapo"
    ) {
      return 11;
    }
    if (code.includes("ceremonie") || code.includes("cérémonie")) return 12;
    return 1;
  }

  function injectRecreatedStepperCss() {
    const styleId = "anf-recreated-stepper-style";
    let styleEl = document.getElementById(styleId);
    if (!styleEl) {
      styleEl = document.createElement("style");
      styleEl.id = styleId;
      document.head.appendChild(styleEl);
    }
    styleEl.textContent = `
      #anf-extension-stepper-root,
      #anf-extension-stepper-root * {
        box-sizing: border-box;
      }
      #anf-extension-stepper-root {
        --anf-bleu: #000091;
        --anf-rouge: #e1000f;
        --anf-ink: #161616;
        --anf-muted: #666;
        --anf-line: #e5e5e5;
        --anf-surface: #ffffff;
        font-family: inherit;
        background: #f8f8fc;
        border-bottom: 1px solid var(--anf-line);
      }
      #anf-extension-stepper-root .anf-stepper-inner {
        position: relative;
        max-width: 1240px;
        margin: 0 auto;
        padding: 10px 14px 12px;
      }
      #anf-extension-stepper-root ol,
      #anf-extension-stepper-root ul,
      #anf-extension-stepper-root li {
        list-style: none !important;
        list-style-type: none !important;
        padding-left: 0 !important;
        margin-left: 0 !important;
      }
      #anf-extension-stepper-root li::marker,
      #anf-extension-stepper-root ol::marker,
      #anf-extension-stepper-root ul::marker {
        content: none !important;
        display: none !important;
      }
      .anf-track-head {
        margin-bottom: 6px;
      }
      .anf-track-title {
        margin: 0;
        color: var(--anf-ink);
        font-size: 14px;
        font-weight: 700;
        line-height: 1.25;
      }
      .anf-track-progress-wrap {
        margin-bottom: 8px;
      }
      .anf-track-progress-meta {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
        color: var(--anf-muted);
        font-size: 10px;
      }
      .anf-track-progress-meta strong {
        color: var(--anf-ink);
        font-size: 11px;
        font-weight: 700;
      }
      .anf-track-progress {
        height: 3px;
        border-radius: 999px;
        background: #ececf3;
        overflow: hidden;
      }
      .anf-track-progress-fill {
        height: 100%;
        border-radius: inherit;
        background: linear-gradient(90deg, var(--anf-bleu), #6a6af4);
      }
      .anf-track-rail {
        margin: 0;
        padding: 0;
        overflow: visible;
      }
      .anf-macro-track {
        display: flex;
        flex-direction: column;
        gap: 0;
      }
      .anf-macro-block {
        width: 100%;
      }
      .anf-macro-block-inner {
        display: flex;
        gap: 16px;
        align-items: flex-start;
        width: 100%;
        padding: 16px 18px;
        border-radius: 12px;
        border: 2px solid #e3e3ef;
        background: #fff;
        box-shadow: 0 4px 18px rgba(0, 0, 145, 0.05);
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
      }
      .anf-macro-block.is-done .anf-macro-block-inner {
        border-color: #22c55e;
        background: linear-gradient(135deg, #f0fdf4 0%, #ffffff 100%);
      }
      .anf-macro-block.is-current .anf-macro-block-inner {
        border-color: var(--anf-rouge);
        background: linear-gradient(135deg, #fff5f5 0%, #ffffff 100%);
        box-shadow: 0 8px 28px rgba(225, 0, 15, 0.12);
      }
      .anf-macro-block.is-pending .anf-macro-block-inner {
        border-color: #e5e5e5;
        background: #fafafa;
        opacity: 0.88;
      }
      .anf-macro-status-icon {
        flex: 0 0 44px;
        width: 44px;
        height: 44px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        background: #f3f3f8;
      }
      .anf-macro-status-icon svg {
        width: 24px;
        height: 24px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .anf-macro-status-icon.is-done {
        color: #16a34a;
        background: #dcfce7;
      }
      .anf-macro-status-icon.is-done svg circle {
        fill: #16a34a;
        stroke: #16a34a;
      }
      .anf-macro-status-icon.is-done svg path {
        stroke: #fff;
        stroke-width: 2.5;
      }
      .anf-macro-status-icon.is-pending {
        color: #9ca3af;
        background: #f3f4f6;
      }
      .anf-macro-status-icon.is-current {
        color: #d97706;
        background: #fff7ed;
        animation: anf-hourglass-pulse 2s ease-in-out infinite;
      }
      @keyframes anf-hourglass-pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.06); }
      }
      .anf-macro-connector {
        width: 2px;
        height: 18px;
        margin: 0 auto;
        background: linear-gradient(180deg, #c5c5d8, #a5a5c0);
        border-radius: 999px;
      }
      .anf-macro-connector.is-done {
        background: linear-gradient(180deg, #4ade80, #16a34a);
      }
      .anf-macro-content {
        flex: 1;
        min-width: 0;
      }
      .anf-macro-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 4px;
      }
      .anf-macro-title {
        margin: 0;
        font-size: 16px;
        font-weight: 800;
        color: var(--anf-ink);
        line-height: 1.2;
      }
      .anf-macro-block.is-done .anf-macro-title { color: #15803d; }
      .anf-macro-block.is-current .anf-macro-title { color: var(--anf-rouge); }
      .anf-macro-block.is-pending .anf-macro-title { color: #9ca3af; }
      .anf-macro-badge {
        flex-shrink: 0;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }
      .anf-macro-block.is-done .anf-macro-badge {
        background: #dcfce7;
        color: #15803d;
      }
      .anf-macro-block.is-current .anf-macro-badge {
        background: #fee2e2;
        color: var(--anf-rouge);
      }
      .anf-macro-block.is-pending .anf-macro-badge {
        background: #f3f4f6;
        color: #9ca3af;
      }
      .anf-macro-subtitle {
        margin: 0 0 14px;
        font-size: 12px;
        color: var(--anf-muted);
        line-height: 1.4;
      }
      .anf-phase-stepper-wrap {
        display: flex;
        justify-content: center;
        width: 100%;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: thin;
      }
      .anf-phase-stepper {
        display: flex;
        align-items: flex-start;
        justify-content: center;
        flex: 0 1 auto;
        width: max-content;
        max-width: 100%;
        margin: 0 auto;
        padding: 14px 0 4px;
        gap: 0;
      }
      .anf-phase-stepper .anf-track-step {
        flex: 0 1 148px;
        width: 148px;
        min-width: 112px;
        max-width: 168px;
        display: flex;
        flex-direction: column;
        overflow: visible;
      }
      .anf-step-track {
        position: relative;
        display: flex;
        align-items: center;
        width: 100%;
        height: 36px;
        overflow: visible;
      }
      .anf-step-line {
        position: relative;
        flex: 1 1 0;
        min-width: 8px;
        height: 2px;
        background: #d4d4e0;
        border-radius: 999px;
        transition: background 0.25s ease;
      }
      .anf-step-line.is-done {
        background: var(--anf-bleu);
      }
      .anf-step-line.is-hidden {
        visibility: hidden;
      }
      .anf-step-duration {
        position: absolute;
        left: 0;
        top: 50%;
        z-index: 2;
        transform: translate(-50%, calc(-100% - 5px));
        padding: 1px 5px;
        border-radius: 4px;
        background: #f0f0f8;
        color: #5c5c78;
        font-size: 8.5px;
        font-weight: 700;
        line-height: 1.2;
        white-space: nowrap;
        pointer-events: none;
      }
      .anf-step-duration.is-done {
        background: #eef0ff;
        color: #3b3b9e;
      }
      .anf-step-node {
        position: relative;
        z-index: 1;
        flex: 0 0 34px;
        width: 34px;
        height: 34px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        border: 2px solid #d0d0de;
        background: #fff;
        transition: border-color 0.2s ease, background 0.2s ease, box-shadow 0.2s ease;
      }
      .anf-track-step-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 18px;
        height: 18px;
        color: #7b7b96;
        flex-shrink: 0;
      }
      .anf-track-step-icon svg {
        display: block;
        width: 16px;
        height: 16px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .anf-track-step.is-done .anf-step-node {
        border-color: var(--anf-bleu);
        background: var(--anf-bleu);
        box-shadow: 0 2px 8px rgba(0, 0, 145, 0.22);
      }
      .anf-track-step.is-done .anf-track-step-icon {
        color: #fff;
      }
      .anf-track-step.is-current .anf-step-node {
        border-color: var(--anf-rouge);
        background: #fff;
        box-shadow: 0 0 0 4px rgba(225, 0, 15, 0.12);
        animation: anf-node-pulse 2.4s ease-in-out infinite;
      }
      .anf-track-step.is-current .anf-track-step-icon {
        color: var(--anf-rouge);
      }
      .anf-track-step.is-pending .anf-step-node {
        border-color: #e2e2ec;
        background: #f6f6fa;
      }
      .anf-track-step.is-pending .anf-track-step-icon {
        color: #b0b0be;
      }
      @keyframes anf-node-pulse {
        0%, 100% { box-shadow: 0 0 0 4px rgba(225, 0, 15, 0.1); }
        50% { box-shadow: 0 0 0 7px rgba(225, 0, 15, 0.16); }
      }
      .anf-step-copy {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 4px;
        padding: 10px 6px 0;
        text-align: center;
      }
      .anf-track-step.is-current .anf-step-copy {
        padding-top: 8px;
        margin-top: 2px;
        border-radius: 8px;
        background: rgba(225, 0, 15, 0.03);
      }
      .anf-track-step-title {
        margin: 0;
        width: 100%;
        font-size: 11px;
        font-weight: 700;
        line-height: 1.35;
        color: var(--anf-ink);
        word-break: break-word;
      }
      .anf-track-step.is-done .anf-track-step-title {
        color: var(--anf-bleu);
      }
      .anf-track-step.is-current .anf-track-step-title {
        color: var(--anf-rouge);
        font-size: 11.5px;
      }
      .anf-track-step.is-pending .anf-track-step-title {
        color: #9b9b9b;
        font-weight: 600;
      }
      .anf-track-step-details {
        display: flex;
        flex-direction: column;
        align-items: stretch;
        gap: 3px;
        width: 100%;
        margin-top: 2px;
      }
      .anf-track-step-details:empty {
        display: none;
      }
      .anf-track-step-detail {
        display: block;
        width: 100%;
        color: var(--anf-muted);
        font-size: 9.5px;
        font-weight: 500;
        line-height: 1.35;
        text-align: center;
        white-space: normal;
        word-break: break-word;
      }
      .anf-track-step-detail.is-date {
        color: #5c5c78;
        font-size: 9px;
      }
      .anf-track-step-detail.is-status-card {
        padding: 5px 6px;
        border-radius: 6px;
        border: 1px solid rgba(0, 0, 145, 0.1);
        background: #f7f7fd;
        color: var(--anf-ink);
        font-size: 9.5px;
        font-weight: 600;
        line-height: 1.35;
      }
      .anf-track-step.is-current .anf-track-step-detail.is-status-card {
        border-color: rgba(225, 0, 15, 0.18);
        background: #fff;
      }
      .anf-track-step-detail.is-status-time {
        color: var(--anf-rouge);
        font-size: 9px;
        font-weight: 600;
      }
      .anf-track-step-detail.is-decret-card {
        padding: 5px 6px;
        border-radius: 6px;
        border: 1px solid #9be9b0;
        background: #f3fff6;
        color: #18794e;
        font-size: 9.5px;
        white-space: pre-line;
      }
      .anf-track-step-detail.is-link {
        color: var(--anf-bleu);
        text-decoration: none;
        font-weight: 700;
      }
      .anf-track-step-detail.is-link:hover { text-decoration: underline; }
      .anf-track-masked-row {
        display: inline-flex !important;
        align-items: center;
        justify-content: center;
        gap: 5px;
        cursor: pointer;
        width: auto !important;
      }
      .anf-toggle-plateforme {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 14px;
        height: 14px;
        color: var(--anf-bleu);
        flex-shrink: 0;
      }
      .anf-toggle-plateforme svg {
        display: block;
        width: 14px;
        height: 14px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
      .anf-stepper-version {
        color: #aaa;
        font-size: 9px;
        font-weight: 500;
        white-space: nowrap;
      }
      @media (max-width: 640px) {
        .anf-macro-block-inner {
          flex-direction: column;
          gap: 12px;
          padding: 14px;
        }
        .anf-macro-status-icon {
          flex: 0 0 40px;
          width: 40px;
          height: 40px;
        }
        .anf-macro-title { font-size: 15px; }
        .anf-phase-stepper .anf-track-step {
          flex: 0 1 120px;
          width: 120px;
          min-width: 96px;
          max-width: 128px;
        }
        .anf-step-node {
          flex: 0 0 30px;
          width: 30px;
          height: 30px;
        }
        .anf-track-step-icon svg {
          width: 14px;
          height: 14px;
        }
        .anf-track-step-title {
          font-size: 10px;
        }
        .anf-track-step-detail {
          font-size: 9px;
        }
        .anf-step-duration {
          font-size: 7.5px;
          padding: 1px 3px;
        }
      }
    `;
  }

  function createStepDetail(text, variant) {
    const el = document.createElement("span");
    el.className = `anf-track-step-detail${variant ? ` is-${variant}` : ""}`;
    el.textContent = text;
    return el;
  }

  function appendStepDetails(item, stepKey, index, currentIndex, apiInfos) {
    const {
      statutDescription: dossierStatus,
      statutCode: dossierStatusCode,
      dateStatut,
      dateStatutRelative,
      demandeDate,
      complementInstructionDate,
      assimilationDate,
      assimilationPlateforme,
      recepisseCreated,
      decretId,
    } = apiInfos;
    const isCurrent = index === currentIndex;
    const details = [];
    const anchorRawDate = getStepAnchorRawDate(
      stepKey,
      index,
      currentIndex,
      apiInfos
    );

    if (stepKey === "demande_envoyee" && demandeDate) {
      details.push({ text: formatDate(demandeDate), variant: "date" });
    }
    if (stepKey === "examen_pieces" && complementInstructionDate) {
      details.push({
        text: `Complément demandé le ${formatDate(complementInstructionDate)}`,
        variant: "date",
      });
    }
    if (stepKey === "demande_deposee" && anchorRawDate) {
      details.push({ text: formatDate(anchorRawDate), variant: "date" });
    }
    if (stepKey === "recepisse_completude" && recepisseCreated) {
      details.push({ text: formatDate(recepisseCreated), variant: "date" });
    }
    if (stepKey === "entretien_assimilation") {
      if (assimilationDate) {
        details.push({ text: formatDate(assimilationDate), variant: "date" });
      }
      if (assimilationPlateforme) {
        details.push({
          text: "************",
          revealText: assimilationPlateforme,
          variant: "date",
          masked: true,
        });
      }
    }
    if (isCurrent && dateStatut) {
      const statusDateLabel = formatDate(dateStatut);
      const alreadyShown = details.some(
        (detail) =>
          detail.text === statusDateLabel ||
          detail.text?.includes(statusDateLabel)
      );
      if (!alreadyShown) {
        details.unshift({ text: statusDateLabel, variant: "date" });
      }
    }
    if (isCurrent && !["decision_prise", "ceremonie_naturalisation"].includes(stepKey)) {
      details.push({ text: dossierStatus, variant: "status-card" });
      if (dateStatutRelative) {
        details.push({ text: `(${dateStatutRelative})`, variant: "status-time" });
      }
    }
    if (stepKey === "decision_prise") {
      if (isCurrent) {
        details.push({ text: dossierStatus, variant: "status-card" });
        if (dateStatutRelative) {
          details.push({ text: `(${dateStatutRelative})`, variant: "status-time" });
        }
      }
      if (decretId) {
        details.push({
          text: `Décret de Naturalisation\nN° ${decretId}`,
          variant: "decret-card",
        });
        details.push({
          text: "LégiFrance",
          variant: "link",
          href: "https://www.legifrance.gouv.fr/search/all?tab_selection=all&searchField=ALL&query=nationalit%C3%A9+fran%C3%A7aise&page=1&init=true",
        });
      }
    }

    const wrapper = document.createElement("div");
    wrapper.className = "anf-track-step-details";
    if (!details.length) {
      item.appendChild(wrapper);
      return;
    }

    details.forEach((detail) => {
      if (detail.href) {
        const el = document.createElement("a");
        el.className = `anf-track-step-detail is-${detail.variant}`;
        el.textContent = detail.text;
        el.href = detail.href;
        el.target = "_blank";
        el.rel = "noopener noreferrer";
        wrapper.appendChild(el);
        return;
      }

      if (detail.masked && detail.revealText) {
        const row = document.createElement("span");
        row.className = `anf-track-step-detail is-${detail.variant} anf-track-masked-row`;

        const textSpan = document.createElement("span");
        textSpan.textContent = detail.text;

        let hidden = true;
        const icon = createVisibilityToggleIcon(hidden);
        icon.setAttribute(
          "title",
          hidden ? "Afficher la plateforme" : "Masquer la plateforme"
        );

        const toggleMasked = (e) => {
          e.stopPropagation();
          hidden = !hidden;
          textSpan.textContent = hidden ? detail.text : detail.revealText;
          icon.innerHTML = hidden
            ? VISIBILITY_ICON_SVG.hidden
            : VISIBILITY_ICON_SVG.visible;
          icon.setAttribute(
            "title",
            hidden ? "Afficher la plateforme" : "Masquer la plateforme"
          );
        };

        row.onclick = toggleMasked;
        row.appendChild(textSpan);
        row.appendChild(icon);
        wrapper.appendChild(row);
        return;
      }

      const el = createStepDetail(detail.text, detail.variant);
      wrapper.appendChild(el);
    });
    item.appendChild(wrapper);
  }

  function renderRecreatedStepper(apiInfos) {
    const header = document.querySelector("anef-header");
    if (!header) {
      console.log("Warning: Extension API Naturalisation — anef-header introuvable");
      return false;
    }

    injectRecreatedStepperCss();

    const inferredIndex = inferRecreatedTrackingIndex(apiInfos.statutCode);
    const currentIndex = Math.min(
      RECREATED_TRACKING_STEPS.length - 1,
      apiInfos.decretId ? Math.max(inferredIndex, 11) : inferredIndex
    );

    let root = document.getElementById("anf-extension-stepper-root");
    if (!root) {
      root = document.createElement("section");
      root.id = "anf-extension-stepper-root";
      header.insertAdjacentElement("afterend", root);
    }

    const progressPct = getMacroProgressPct(currentIndex);
    const currentStepTitle = RECREATED_TRACKING_STEPS[currentIndex]?.title || "";
    const currentPhase =
      MACRO_PHASES.find(
        (phase) =>
          currentIndex >= phase.startIndex && currentIndex <= phase.endIndex
      ) || MACRO_PHASES[MACRO_PHASES.length - 1];

    root.innerHTML = `
      <div class="anf-stepper-inner">
        <div class="anf-track-head">
          <h2 class="anf-track-title">Demande d'accès à la Nationalité Française</h2>
        </div>
        <div class="anf-track-progress-wrap">
          <div class="anf-track-progress-meta">
            <span><strong>${currentPhase.title}</strong> · ${currentStepTitle}</span>
            <span>${progressPct}% · <span class="anf-stepper-version">v${extensionVersion}</span></span>
          </div>
          <div class="anf-track-progress" aria-hidden="true">
            <div class="anf-track-progress-fill" style="width:${progressPct}%"></div>
          </div>
        </div>
        <div class="anf-track-rail" role="list" aria-label="Étapes du dossier"></div>
      </div>
    `;

    const list = root.querySelector(".anf-track-rail");
    list.classList.add("anf-macro-track");

    const trackFragment = document.createDocumentFragment();
    MACRO_PHASES.forEach((phase, phaseIndex) => {
      trackFragment.appendChild(
        buildMacroPhaseBlock(phase, currentIndex, apiInfos)
      );
      if (phaseIndex < MACRO_PHASES.length - 1) {
        const connector = document.createElement("div");
        connector.className = "anf-macro-connector";
        if (currentIndex > phase.endIndex) {
          connector.classList.add("is-done");
        }
        connector.setAttribute("aria-hidden", "true");
        trackFragment.appendChild(connector);
      }
    });
    list.appendChild(trackFragment);

    requestAnimationFrame(() => {
      const currentStep = list.querySelector(".anf-track-step.is-current");
      if (currentStep) {
        currentStep.scrollIntoView({
          behavior: "smooth",
          block: "nearest",
          inline: "center",
        });
      } else {
        const currentBlock = list.querySelector(".anf-macro-block.is-current");
        if (currentBlock) {
          currentBlock.scrollIntoView({
            behavior: "smooth",
            block: "nearest",
          });
        }
      }
    });

    console.log(
      `Extension API Naturalisation : stepper injecté (${currentIndex + 1}/${RECREATED_TRACKING_STEPS.length})`
    );
    return true;
  }

  function waitForAnefHeader(timeoutMs = 5000) {
    return new Promise((resolve) => {
      if (document.querySelector("anef-header")) {
        resolve(true);
        return;
      }

      let settled = false;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        observer.disconnect();
        clearTimeout(timer);
        resolve(value);
      };

      const observer = new MutationObserver(() => {
        if (document.querySelector("anef-header")) finish(true);
      });
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });

      const timer = setTimeout(
        () => finish(Boolean(document.querySelector("anef-header"))),
        timeoutMs
      );
    });
  }

  async function addSeriesVisibilityToggle() {
    try {
      for (let i = 0; i < 20; i++) {
        const tds = Array.from(document.querySelectorAll("td.fixed"));
        const seriesTd = tds.find((td) =>
          /^\d{4}X\s\d+$/.test(td.textContent.trim())
        );
        if (!seriesTd) {
          await sleep(CONFIG.WAIT_TIME);
          continue;
        }
        if (seriesTd.querySelector(".anf-toggle-serie")) return;

        const fullSerie = seriesTd.textContent.trim();
        const spaceIndex = fullSerie.indexOf(" ");
        if (spaceIndex < 0) return;

        const prefix = fullSerie.slice(0, spaceIndex);
        const suffix = fullSerie.slice(spaceIndex + 1).trim();
        if (!prefix || !suffix) return;

        const maskedDisplay = prefix + " " + "*".repeat(suffix.length);
        const fullDisplay = prefix + " " + suffix;
        let isHidden = true;

        seriesTd.textContent = "";
        const textSpan = document.createElement("span");
        textSpan.textContent = maskedDisplay;
        seriesTd.appendChild(textSpan);

        const icon = document.createElement("span");
        icon.className = "anf-toggle-serie";
        icon.innerHTML = VISIBILITY_ICON_SVG.hidden;
        icon.style.marginLeft = "8px";
        icon.style.cursor = "pointer";
        icon.style.color = "#255a99";
        icon.style.display = "inline-flex";
        icon.style.verticalAlign = "middle";
        icon.onclick = function (e) {
          e.stopPropagation();
          isHidden = !isHidden;
          textSpan.textContent = isHidden ? maskedDisplay : fullDisplay;
          icon.innerHTML = isHidden
            ? VISIBILITY_ICON_SVG.hidden
            : VISIBILITY_ICON_SVG.visible;
        };
        seriesTd.appendChild(icon);
        return;
      }
    } catch (error) {
      console.log(
        "Warning: Extension API Naturalisation — toggle série ignoré:",
        error
      );
    }
  }

  async function addFiscalStampVisibilityToggle() {
    try {
      for (let i = 0; i < 20; i++) {
        const tds = Array.from(document.querySelectorAll("td.fixed"));
        const fiscalTd = tds.find((td) => /^\d{16}$/.test(td.textContent.trim()));
        if (!fiscalTd) {
          await sleep(CONFIG.WAIT_TIME);
          continue;
        }
        if (fiscalTd.querySelector(".anf-toggle-fiscal")) return;

        const fullStamp = fiscalTd.textContent.trim();
        if (!fullStamp) return;

        const maskedStamp = "*".repeat(fullStamp.length);
        let isHidden = true;

        fiscalTd.textContent = "";
        const textSpan = document.createElement("span");
        textSpan.textContent = maskedStamp;
        fiscalTd.appendChild(textSpan);

        const icon = document.createElement("span");
        icon.className = "anf-toggle-fiscal";
        icon.innerHTML = VISIBILITY_ICON_SVG.hidden;
        icon.style.marginLeft = "8px";
        icon.style.cursor = "pointer";
        icon.style.color = "#255a99";
        icon.style.display = "inline-flex";
        icon.style.verticalAlign = "middle";
        icon.onclick = function (e) {
          e.stopPropagation();
          isHidden = !isHidden;
          textSpan.textContent = isHidden ? maskedStamp : fullStamp;
          icon.innerHTML = isHidden
            ? VISIBILITY_ICON_SVG.hidden
            : VISIBILITY_ICON_SVG.visible;
        };
        fiscalTd.appendChild(icon);
        return;
      }
    } catch (error) {
      console.log(
        "Warning: Extension API Naturalisation — toggle timbre ignoré:",
        error
      );
    }
  }

  function showStepperIfReady(apiInfos, hasHeader) {
    if (!hasNaturalisationData(apiInfos) || !hasHeader) return false;
    renderRecreatedStepper(apiInfos);
    return true;
  }

  let bootstrapRunning = false;
  let bootstrapTimer = null;
  let authObserver = null;

  function stopAuthObserver() {
    authObserver?.disconnect();
    authObserver = null;
  }

  function watchForLogin() {
    if (authObserver) return;

    authObserver = new MutationObserver(() => {
      if (getAuthState() === "logged-in") {
        stopAuthObserver();
        scheduleBootstrap(500);
      }
    });

    authObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  async function bootstrap() {
    if (bootstrapRunning) return;
    bootstrapRunning = true;

    try {
      const hasHeader = await waitForAnefHeader();
      if (!hasHeader) return;

      const authState = await waitForAuthResolved();

      if (authState !== "logged-in") {
        removeStepperIfPresent();
        if (authState === "logged-out") {
          watchForLogin();
        }
        return;
      }

      stopAuthObserver();

      if (isOAuthCallback()) {
        await sleep(1500);
      }

      const apiInfos = await fetchApiInfos();

      if (!hasNaturalisationData(apiInfos)) {
        removeStepperIfPresent();
        return;
      }

      showStepperIfReady(apiInfos, true);

      enrichApiInfos(apiInfos)
        .then((enriched) => {
          logApiInfos(enriched);
          showStepperIfReady(enriched, true);
          addSeriesVisibilityToggle();
          addFiscalStampVisibilityToggle();
        })
        .catch((error) => {
          console.log(
            "Warning: Extension API Naturalisation — enrichissement partiel:",
            error
          );
          logApiInfos(apiInfos);
        });
    } catch (error) {
      console.log(
        "Error: Extension API Naturalisation — erreur inattendue:",
        error
      );
      removeStepperIfPresent();
    } finally {
      bootstrapRunning = false;
    }
  }

  function scheduleBootstrap(delayMs = 0) {
    clearTimeout(bootstrapTimer);
    bootstrapTimer = setTimeout(() => {
      bootstrap();
    }, delayMs);
  }

  scheduleBootstrap();

  window.addEventListener("hashchange", () => {
    if (isOAuthCallback()) return;
    scheduleBootstrap(1500);
  });
})();