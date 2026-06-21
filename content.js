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

  function prefersReducedMotion() {
    return Boolean(
      window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
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
  const extensionVersion = "3.6.5";
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
    const info = STATUTS[status];
    if (info) {
      const prefix = getStatusGroupLabel(info.etape, status);
      return prefix ? `${prefix} : ${info.explication}` : info.explication;
    }

    // Fallback pour les codes non couverts par STATUTS (vérifié en premier).
    const statusMap = {
      // Variante tronquée parfois renvoyée par l'API
      prop_decision_pref_en_attente_retour_hierarchiqu:
        "Préfecture : En attente retour hiérarchique",
      // Prénaturalisation
      prenat_a_traiter: "Prenaturalisation : À traiter",
      prenat_en_cours: "Prenaturalisation : En cours",
      prenat_en_attente_complements:
        "Prenaturalisation : En attente compléments",
      prenat_cloture: "Prenaturalisation : Clôturée",
      // SCEC
      scec_a_faire: "SCEC à faire",
      scec_en_cours: "SCEC en cours",
      scec_en_attente: "SCEC en attente",
      scec_bloque: "SCEC bloqué",
      scec_termine: "SCEC terminé",
      non_applicable: "SCEC non attribuable",
      // Fallback générique
      code_non_reconnu: "Code non reconnu",
    };

    return statusMap[status] || status || statusMap["code_non_reconnu"];
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

    let months = Math.floor(diffDays / 30);
    const days = diffDays % 30;
    const years = Math.floor(months / 12);
    months = months % 12;

    const parts = [];
    if (years > 0) {
      parts.push(`${years} ${years === 1 ? "an" : "ans"}`);
    }
    if (months > 0) {
      parts.push(`${months} mois`);
    }
    if (days > 0) {
      parts.push(`${days} jrs`);
    }

    if (parts.length === 1) return parts[0];
    if (parts.length === 2) return `${parts[0]} et ${parts[1]}`;
    return `${parts[0]} et ${parts[1]} et ${parts[2]}`;
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
      case "dossier_depose":
        return resolveDemandeDeposeeRawDate(apiInfos, index, currentIndex);
      case "recepisse_completude":
        return recepisseCreated;
      case "entretien_assimilation":
        return assimilationDate;
      case "compte_rendu_assimilation":
        return index === currentIndex ? dateStatut : null;
      case "decision_prise":
      case "decret_naturalisation_publie":
      case "inseree_dans_decret":
        return decretDate || (decretId && index === currentIndex ? dateStatut : null);
      case "ceremonie_naturalisation":
      case "recours_envoye":
      case "recours_statut_courant":
      case "recours_decision_prise":
      case "demande_en_cours_rapo":
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
    console.log("Date statut:", apiInfos.dateStatut);
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

const STATUTS = {
    // ── Étape 1 : Brouillon ──────
    "draft": {
      phase: "Brouillon",
      explication: "Dossier en brouillon",
      etape: 1,
      rang: 100,
      description: "Votre dossier est en cours de préparation sur la plateforme ANEF. Complétez toutes les sections et joignez les pièces justificatives avant de soumettre.",
      icon: "📝"
    },
  
    // ── Étape 2 : Dépôt du dossier 
    "dossier_depose": {
      phase: "Dépôt",
      explication: "Dossier déposé",
      etape: 2,
      rang: 200,
      description: "Votre dossier a été soumis avec succès. Il est dans la file d'attente de la préfecture pour un premier examen de recevabilité.",
      icon: "📨"
    },
  
    // ── Étape 3 : Vérification formelle ──
    "verification_formelle_a_traiter": {
      phase: "Vérification formelle",
      explication: "Dossier reçu, en tri",
      etape: 3,
      rang: 301,
      description: "La préfecture a bien reçu votre demande. Elle est placée en file d'attente pour le premier tri administratif : vérification des pièces obligatoires et conditions de base.",
      icon: "🔍"
    },
    "verification_formelle_en_cours": {
      phase: "Vérification formelle",
      explication: "Tri en cours",
      etape: 3,
      rang: 302,
      description: "Un agent vérifie l'admissibilité formelle de votre dossier : présence des documents requis, validité des pièces, conditions légales. Des compléments peuvent être demandés.",
      icon: "🔍"
    },
    "verification_formelle_mise_en_demeure": {
      phase: "Vérification formelle",
      explication: "Mise en demeure, pièces à fournir",
      etape: 3,
      rang: 303,
      description: "Des documents obligatoires sont manquants ou non conformes. Vous allez recevoir un courrier détaillant les pièces à fournir. Répondez dans le délai imparti pour éviter un classement sans suite.",
      icon: "⚠️"
    },
    "css_mise_en_demeure_a_affecter": {
      phase: "Vérification formelle",
      explication: "Classement sans suite en cours",
      etape: 3,
      rang: 304,
      description: "Suite à la mise en demeure restée sans réponse, un classement sans suite est en cours d'affectation à un agent. Fournissez les pièces manquantes au plus vite.",
      icon: "⚠️"
    },
    "css_mise_en_demeure_a_rediger": {
      phase: "Vérification formelle",
      explication: "Classement sans suite en rédaction",
      etape: 3,
      rang: 305,
      description: "Le classement sans suite de votre dossier est en cours de rédaction suite à l'absence de réponse à la mise en demeure. Contactez votre préfecture si vous avez transmis les pièces.",
      icon: "⚠️"
    },
  
    // ── Étape 4 : Affectation instructeur 
    "instruction_a_affecter": {
      phase: "Affectation",
      explication: "Dossier recevable, attente d'affectation",
      etape: 4,
      rang: 400,
      description: "Votre dossier a passé la vérification formelle avec succès ! Il est déclaré recevable et attend d'être attribué à un agent instructeur pour un examen approfondi. Vous recevrez un récépissé de dépôt.",
      icon: "👤"
    },
  
    // ── Étape 5 : Instruction du dossier ─
    "instruction_recepisse_completude_a_envoyer": {
      phase: "Instruction",
      explication: "Dossier complet, examen approfondi",
      etape: 5,
      rang: 501,
      description: "Un agent instructeur examine en détail votre dossier : situation personnelle, professionnelle, fiscale, assimilation. Le récépissé de complétude sera envoyé. Il peut vous convoquer pour l'entretien.",
      icon: "📖"
    },
    "instruction_recepisse_completude_a_envoyer_retour_complement_a_traiter": {
      phase: "Instruction",
      explication: "Compléments reçus, à vérifier",
      etape: 5,
      rang: 502,
      description: "Vous avez fourni des documents complémentaires suite à une demande de l'instructeur. L'agent vérifie leur conformité avant de poursuivre l'instruction de votre dossier.",
      icon: "📋"
    },
    "css_manuels_a_affecter": {
      phase: "Classement sans suite",
      explication: "Proposition de CSS manuel, à affecter",
      etape: 5,
      rang: 503,
      description: "Un agent a proposé un classement sans suite de votre dossier (réponse à un complément jugée insuffisante, désistement présumé, ou autre motif). La proposition attend d'être affectée à un agent pour rédaction. Ce n'est pas encore une décision notifiée : contactez rapidement votre préfecture pour fournir les pièces manquantes ou clarifier votre situation.",
      icon: "⚠️"
    },
    "css_manuels_a_rediger": {
      phase: "Classement sans suite",
      explication: "CSS manuel, rédaction en cours",
      etape: 5,
      rang: 504,
      description: "La proposition de classement sans suite manuel est en cours de rédaction par un agent. Ce n'est pas encore une décision notifiée : contactez rapidement votre préfecture si vous avez transmis les pièces demandées.",
      icon: "⚠️"
    },
    "css_automatiques_a_affecter": {
      phase: "Classement sans suite",
      explication: "Proposition de CSS automatique, à affecter",
      etape: 5,
      rang: 505,
      description: "Le système a automatiquement proposé un classement sans suite (absence de réponse dans les délais impartis). La proposition attend d'être affectée à un agent pour rédaction. Contactez rapidement votre préfecture pour fournir les pièces manquantes.",
      icon: "⚠️"
    },
    "css_automatiques_a_rediger": {
      phase: "Classement sans suite",
      explication: "CSS automatique, rédaction en cours",
      etape: 5,
      rang: 506,
      description: "Un classement sans suite automatique (déclenché par le système) est en cours de rédaction. Contactez rapidement votre préfecture si vous avez transmis les pièces demandées.",
      icon: "⚠️"
    },
  
    // ── Étape 6 : Complétude & enquêtes ──
    "instruction_date_ea_a_fixer": {
      phase: "Complétude & enquêtes",
      explication: "Enquêtes administratives lancées",
      etape: 6,
      rang: 601,
      description: "Votre dossier est officiellement complet ! Les enquêtes administratives obligatoires sont lancées (casier judiciaire, renseignements, fichiers). La date d'entretien d'assimilation sera fixée prochainement.",
      icon: "🔎"
    },
    "ea_demande_report_ea": {
      phase: "Complétude & enquêtes",
      explication: "Demande de report d'entretien",
      etape: 6,
      rang: 602,
      description: "Une demande de report de l'entretien d'assimilation a été enregistrée. La préfecture vous proposera une nouvelle date. Attention aux délais pour ne pas retarder votre dossier.",
      icon: "🔄"
    },
  
    // ── Étape 7 : Entretien d'assimilation 
    "ea_en_attente_ea": {
      phase: "Entretien d'assimilation",
      explication: "Convocation envoyée, en attente",
      etape: 7,
      rang: 701,
      description: "Votre convocation à l'entretien d'assimilation est envoyée ou disponible. Préparez-vous : questions sur la France (histoire, culture, valeurs républicaines), votre parcours et vos motivations.",
      icon: "📬"
    },
    "ea_crea_a_valider": {
      phase: "Entretien d'assimilation",
      explication: "Entretien passé, compte-rendu en rédaction",
      etape: 7,
      rang: 702,
      description: "Vous avez passé l'entretien d'assimilation ! L'agent rédige le compte-rendu évaluant votre niveau de langue, connaissance de la France et assimilation à la communauté française.",
      icon: "✅"
    },
  
    // ── Étape 8 : Décision préfecture ────
    "prop_decision_pref_a_effectuer": {
      phase: "Décision préfecture",
      explication: "Avis préfectoral en cours",
      etape: 8,
      rang: 801,
      description: "L'agent instructeur analyse l'ensemble de votre dossier (enquêtes, entretien, pièces) pour formuler sa proposition d'avis : favorable, défavorable ou ajournement.",
      icon: "⚖️"
    },
    "prop_decision_pref_en_attente_retour_hierarchique": {
      phase: "Décision préfecture",
      explication: "Validation hiérarchique en cours",
      etape: 8,
      rang: 802,
      description: "La proposition de l'agent est soumise à sa hiérarchie pour validation. Cette étape permet de confirmer l'avis avant transmission au préfet. Durée variable selon les préfectures.",
      icon: "👔"
    },
    "prop_decision_pref_prop_a_editer": {
      phase: "Décision préfecture",
      explication: "Rédaction de la proposition",
      etape: 8,
      rang: 803,
      description: "L'avis est validé et le document officiel de proposition est en cours de rédaction. Il résume votre situation et la recommandation de la préfecture au ministère.",
      icon: "📝"
    },
    "prop_decision_pref_en_attente_retour_signataire": {
      phase: "Décision préfecture",
      explication: "Attente signature du préfet",
      etape: 8,
      rang: 804,
      description: "Le document de proposition est finalisé et transmis au préfet (ou son représentant) pour signature. Une fois signé, votre dossier sera envoyé au ministère de l'Intérieur (SDANF).",
      icon: "✍️"
    },
  
    // ── Étape 9 : Contrôle SDANF 
    "controle_a_affecter": {
      phase: "Contrôle SDANF",
      explication: "Arrivé à la SDANF, attente affectation",
      etape: 9,
      rang: 901,
      description: "Votre dossier est arrivé à la Sous-Direction de l'Accès à la Nationalité Française (SDANF) à Rezé (44). Il attend d'être attribué à un agent pour le contrôle ministériel.",
      icon: "🏛️"
    },
    "controle_a_effectuer": {
      phase: "Contrôle SDANF",
      explication: "Contrôle ministériel en cours",
      etape: 9,
      rang: 902,
      description: "Un agent de la SDANF contrôle votre dossier : vérification des pièces d'état civil, cohérence des informations, respect des conditions légales. Cette étape peut prendre plusieurs semaines.",
      icon: "📑"
    },
    // ── Étape 10 : Contrôle SCEC 
    "controle_en_attente_pec": {
      phase: "Contrôle SCEC",
      explication: "Transmis au SCEC de Nantes",
      etape: 10,
      rang: 1001,
      description: "Le Service Central d'État Civil (SCEC) de Nantes vérifie l'authenticité de vos actes d'état civil étrangers. Cette vérification est obligatoire pour valider votre identité.",
      icon: "🏛️"
    },
    "controle_pec_a_faire": {
      phase: "Contrôle SCEC",
      explication: "Vérification d'état civil en cours",
      etape: 10,
      rang: 1002,
      description: "Le SCEC procède à la vérification de vos pièces d'état civil. Une fois validées, vos actes seront transcrits dans les registres français si votre naturalisation aboutit.",
      icon: "✔️"
    },
  
    // ── Étape 11 : Préparation décret ────
    "controle_transmise_pour_decret": {
      phase: "Préparation décret",
      explication: "Avis FAVORABLE, transmis pour décret",
      etape: 11,
      rang: 1101,
      description: "Excellente nouvelle ! L'avis est FAVORABLE. Votre dossier est transmis au service des décrets pour être inclus dans un prochain décret de naturalisation. La fin approche !",
      icon: "🎉"
    },
    "controle_en_attente_retour_hierarchique": {
      phase: "Préparation décret",
      explication: "Validation hiérarchique ministérielle",
      etape: 11,
      rang: 1102,
      description: "Le projet de décret incluant votre demande est soumis à la validation de la hiérarchie ministérielle. Étape administrative normale avant la finalisation du décret.",
      icon: "👔"
    },
    "controle_decision_a_editer": {
      phase: "Préparation décret",
      explication: "Décision favorable, édition en cours",
      etape: 11,
      rang: 1103,
      description: "La décision favorable est confirmée. Le document officiel du décret incluant votre nom est en cours d'édition. Vous serez bientôt inscrit(e) dans un décret de naturalisation.",
      icon: "📄"
    },
    "controle_en_attente_signature": {
      phase: "Préparation décret",
      explication: "Attente signature ministérielle",
      etape: 11,
      rang: 1104,
      description: "Le décret de naturalisation est finalisé et attend la signature du ministre ou de son représentant. Une fois signé, il sera publié au Journal Officiel.",
      icon: "✍️"
    },
    "transmis_a_ac": {
      phase: "Préparation décret",
      explication: "Transmis à l'administration centrale",
      etape: 11,
      rang: 1105,
      description: "Votre dossier favorable est transmis à l'administration centrale chargée de préparer les décrets. Vous êtes dans la dernière ligne droite de la procédure !",
      icon: "📬"
    },
    "a_verifier_avant_insertion_decret": {
      phase: "Préparation décret",
      explication: "Vérifications finales avant insertion",
      etape: 11,
      rang: 1106,
      description: "Dernières vérifications administratives aléatoires et facultatives avant l'insertion de votre nom dans un décret. On s'assure qu'aucun élément nouveau ne s'oppose à votre naturalisation.",
      icon: "🔎"
    },
    "prete_pour_insertion_decret": {
      phase: "Préparation décret",
      explication: "Validé, prêt pour insertion au décret",
      etape: 11,
      rang: 1107,
      description: "Votre dossier est validé et prêt pour insertion dans le prochain décret. Le passage automatique au statut suivant a lieu chaque lundi entre 9h et 11h — inutile de rafraîchir le week-end.",
      icon: "✅"
    },
    "decret_en_preparation": {
      phase: "Préparation décret",
      explication: "Décret en cours de préparation",
      etape: 11,
      rang: 1108,
      description: "Un décret de naturalisation incluant votre nom est en cours de préparation. Plusieurs dossiers sont regroupés dans chaque décret avant publication au Journal Officiel.",
      icon: "📋"
    },
    "decret_a_qualifier": {
      phase: "Préparation décret",
      explication: "Décret en cours de qualification",
      etape: 11,
      rang: 1109,
      description: "Le décret incluant votre nom est en phase de qualification : catégorisation et vérification du type de décret (naturalisation, réintégration, etc.) avant validation finale.",
      icon: "📋"
    },
    "decret_en_validation": {
      phase: "Préparation décret",
      explication: "Décret en validation finale",
      etape: 11,
      rang: 1110,
      description: "Le décret de naturalisation est en cours de validation finale par les services compétents. Dernière étape administrative avant la signature et la publication.",
      icon: "📋"
    },
  
    // ── Étape 12 : Publication JO 
    "inseree_dans_decret": {
      phase: "Publication JO",
      explication: "Inséré dans un décret signé",
      etape: 12,
      rang: 1201,
      description: "Votre nom est officiellement inscrit dans un décret de naturalisation ! Il attend maintenant la publication au Journal Officiel de la République Française.",
      icon: "🎉"
    },
    "decret_envoye_prefecture": {
      phase: "Publication JO",
      explication: "Décret envoyé à votre préfecture",
      etape: 12,
      rang: 1202,
      description: "Le décret signé a été transmis à votre préfecture. Elle va vous convoquer pour la cérémonie d'accueil dans la citoyenneté française et la remise de votre décret.",
      icon: "📨"
    },
    "notification_envoyee": {
      phase: "Publication JO",
      explication: "Notification officielle envoyée",
      etape: 12,
      rang: 1203,
      description: "La notification officielle de votre naturalisation vous a été envoyée. Vous serez convoqué(e) à la cérémonie d'accueil dans la citoyenneté française.",
      icon: "📬"
    },
  
    // ── Étape 13 : Décision finale 
    // Décisions positives
    "decret_naturalisation_publie": {
      phase: "NATURALISÉ(E)",
      explication: "Décret publié au Journal Officiel",
      etape: 13,
      rang: 1301,
      description: "FÉLICITATIONS ! Votre décret de naturalisation est publié au Journal Officiel de la République Française. Vous êtes officiellement citoyen(ne) français(e) ! Demandez votre acte de naissance français (ADN) au SCEC pour commencer vos démarches CNI et passeport.",
      icon: "🇫🇷"
    },
    "decret_naturalisation_publie_jo": {
      phase: "NATURALISÉ(E)",
      explication: "Décret publié au Journal Officiel",
      etape: 13,
      rang: 1302,
      description: "FÉLICITATIONS ! Votre décret de naturalisation est publié au Journal Officiel. Vous êtes officiellement français(e) ! La préfecture vous convoquera pour la cérémonie. Demandez votre ADN au SCEC pour vos démarches CNI / passeport.",
      icon: "🇫🇷"
    },
    "decret_publie": {
      phase: "NATURALISÉ(E)",
      explication: "Décret publié",
      etape: 13,
      rang: 1303,
      description: "FÉLICITATIONS ! Votre décret de naturalisation est publié. Vous êtes officiellement citoyen(ne) français(e) ! La préfecture vous convoquera pour la cérémonie d'accueil. Demandez votre ADN au SCEC, puis votre carte d'identité en mairie.",
      icon: "🇫🇷"
    },
    "demande_traitee": {
      phase: "Finalisé",
      explication: "Demande entièrement traitée",
      etape: 13,
      rang: 1304,
      description: "Votre demande de naturalisation a été entièrement traitée. Consultez vos courriers ou contactez votre préfecture pour connaître l'issue de votre dossier.",
      icon: "✅"
    },
    // Décisions négatives
    "decision_negative_en_delais_recours": {
      phase: "Décision négative",
      explication: "Défavorable, délai de recours ouvert",
      etape: 13,
      rang: 1305,
      description: "Votre demande a reçu une décision défavorable. Vous disposez d'un délai de 2 mois pour former un recours gracieux auprès du ministre (RAPO) ou un recours contentieux devant le tribunal administratif.",
      icon: "❌"
    },
    "decision_notifiee": {
      phase: "Décision négative",
      explication: "Décision notifiée au demandeur",
      etape: 13,
      rang: 1306,
      description: "La décision concernant votre dossier vous a été officiellement notifiée. Consultez le courrier pour connaître la nature de la décision et les voies de recours disponibles.",
      icon: "❌"
    },
    "demande_en_cours_rapo": {
      phase: "Recours RAPO",
      explication: "Recours administratif en cours",
      etape: 13,
      rang: 1307,
      description: "Votre recours administratif préalable obligatoire (RAPO) est en cours d'examen par le ministère. Le RAPO est un recours gracieux contre une décision défavorable. Délai de réponse : environ 4 mois.",
      icon: "⚖️"
    },
    "controle_demande_notifiee": {
      phase: "Décision notifiée",
      explication: "Décision de contrôle notifiée",
      etape: 13,
      rang: 1308,
      description: "La décision issue du contrôle ministériel vous a été officiellement communiquée. Vérifiez vos courriers pour connaître la suite donnée à votre dossier.",
      icon: "📬"
    },
    // Irrecevabilité
    "irrecevabilite_manifeste": {
      phase: "Irrecevabilité",
      explication: "Conditions légales non remplies",
      etape: 13,
      rang: 1309,
      description: "Votre demande ne remplit pas les conditions légales de recevabilité (durée de résidence, titre de séjour, etc.). Vérifiez les critères d'éligibilité avant de déposer une nouvelle demande.",
      icon: "❌"
    },
    "irrecevabilite_manifeste_en_delais_recours": {
      phase: "Irrecevabilité",
      explication: "Irrecevable, délai de recours ouvert",
      etape: 13,
      rang: 1310,
      description: "Votre demande a été déclarée irrecevable. Vous pouvez contester cette décision par un recours gracieux (RAPO) ou contentieux dans un délai de 2 mois.",
      icon: "❌"
    },
    // Classement sans suite
    "css_en_delais_recours": {
      phase: "Classement sans suite",
      explication: "Classé sans suite, recours possible",
      etape: 13,
      rang: 1311,
      description: "Votre dossier a été classé sans suite (pièces non fournies dans les délais, désistement, etc.). Vous pouvez former un recours ou déposer une nouvelle demande complète.",
      icon: "⚠️"
    },
    "css_notifie": {
      phase: "Classement sans suite",
      explication: "Classement sans suite notifié",
      etape: 13,
      rang: 1312,
      description: "Le classement sans suite de votre dossier vous a été officiellement notifié. Analysez les motifs indiqués avant d'envisager une nouvelle demande.",
      icon: "⚠️"
    }
  };

  const STEP_GROUPS = [
    {
      key: "prefecture",
      label: "Préfecture",
      subtitle: "Dépôt, instruction, entretien et décision préfectorale",
      etapes: [2, 3, 4, 5, 6, 7, 8],
    },
    {
      key: "sdanf",
      label: "SDANF",
      subtitle: "Contrôle ministériel à Rezé",
      etapes: [9],
    },
    {
      key: "scec",
      label: "SCEC",
      subtitle: "Validation des pièces d'état civil à Nantes",
      etapes: [10],
    },
    {
      key: "decret",
      label: "Préparation décret",
      subtitle: "Avis favorable, validation et insertion au décret",
      etapes: [11],
    },
    {
      key: "publication",
      label: "Publication JO",
      subtitle: "Insertion, notification et envoi préfecture",
      etapes: [12],
    },
    {
      key: "final",
      label: "Décision finale",
      subtitle: "Naturalisation, refus, recours ou classement sans suite",
      etapes: [13],
    },
    {
      key: "recours",
      label: "Recours",
      subtitle: "Décision défavorable, RAPO et issue du recours",
      etapes: [13],
    },
  ];

  function buildTrackingSteps() {
    const prefecture = [
      { key: "demande_envoyee", code: "draft", group: "prefecture", etape: 1, sub: "1", title: "Demande envoyée" },
      { key: "dossier_depose", code: "dossier_depose", group: "prefecture", etape: 2, sub: "2", title: "Dépôt du dossier", locked: true },
      { key: "examen_pieces", code: "verification_formelle_a_traiter", group: "prefecture", etape: 3, sub: "3", title: "Examen des pièces en cours" },
      { key: "traitement_plateforme_1", group: "prefecture", etape: 4, title: "Traitement en cours (Plateforme)", platform: true },
      { key: "recepisse_completude", code: "instruction_recepisse_completude_a_envoyer", group: "prefecture", etape: 5, sub: "5", title: "Réception du récépissé de complétude" },
      { key: "traitement_plateforme_2", group: "prefecture", etape: 6, title: "Traitement en cours (Plateforme)", platform: true },
      { key: "entretien_assimilation", code: "ea_en_attente_ea", group: "prefecture", etape: 7, sub: "7", title: "Entretien d'assimilation", locked: true },
      { key: "compte_rendu_assimilation", code: "ea_crea_a_valider", group: "prefecture", etape: 7, sub: "7b", title: "Compte-rendu d'assimilation", locked: true },
      { key: "traitement_plateforme_3", group: "prefecture", etape: 8, title: "Traitement en cours (Plateforme)", platform: true },
      { key: "decision_prefecture", code: "prop_decision_pref_a_effectuer", group: "prefecture", etape: 8, sub: "8", title: "Décision préfecture" },
    ];
    const ministry = [
      { key: "traitement_sdanf_1", code: "controle_a_affecter", group: "sdanf", milestone: true, title: "Traitement en cours (SDANF)" },
      { key: "controle_a_effectuer", code: "controle_a_effectuer", group: "sdanf", title: "SDANF — Contrôle en cours" },
      { key: "traitement_scec", code: "controle_en_attente_pec", group: "scec", milestone: true, title: "Traitement en cours (SCEC)" },
      { key: "controle_pec_a_faire", code: "controle_pec_a_faire", group: "scec", title: "SCEC — Vérification en cours" },
      { key: "traitement_sdanf_2", code: "controle_transmise_pour_decret", group: "decret", milestone: true, title: "Traitement en cours (SDANF)" },
      { key: "controle_en_attente_retour_hierarchique", code: "controle_en_attente_retour_hierarchique", group: "decret", title: "Validation hiérarchique ministérielle" },
      { key: "controle_decision_a_editer", code: "controle_decision_a_editer", group: "decret", title: "Décision favorable, édition en cours" },
      { key: "controle_en_attente_signature", code: "controle_en_attente_signature", group: "decret", title: "Attente signature ministérielle" },
      { key: "transmis_a_ac", code: "transmis_a_ac", group: "decret", title: "Transmis à l'administration centrale" },
      { key: "a_verifier_avant_insertion_decret", code: "a_verifier_avant_insertion_decret", group: "decret", title: "Vérifications finales avant insertion" },
      { key: "prete_pour_insertion_decret", code: "prete_pour_insertion_decret", group: "decret", title: "PPID — Prêt pour insertion décret" },
      { key: "decret_en_preparation", code: "decret_en_preparation", group: "decret", title: "Décret en cours de préparation" },
      { key: "decret_a_qualifier", code: "decret_a_qualifier", group: "decret", title: "Décret en cours de qualification" },
      { key: "decret_en_validation", code: "decret_en_validation", group: "decret", title: "Décret en validation finale" },
      { key: "decision_prise", code: "inseree_dans_decret", group: "publication", milestone: true, title: "Décision prise" },
      { key: "decret_envoye_prefecture", code: "decret_envoye_prefecture", group: "publication", title: "Décret envoyé à la préfecture" },
      { key: "notification_envoyee", code: "notification_envoyee", group: "publication", title: "Notification officielle envoyée" },
      { key: "decret_naturalisation_publie", code: "decret_naturalisation_publie", group: "final", milestone: true, title: "Décret publié au Journal Officiel" },
      { key: "ceremonie_naturalisation", group: "final", milestone: true, title: "Cérémonie de naturalisation" },
    ];
    const recours = [
      { key: "recours_envoye", group: "recours", milestone: true, title: "Recours envoyé" },
      { key: "recours_statut_courant", group: "recours", milestone: true, title: "Statut en cours", dynamicTitle: true },
      { key: "recours_decision_prise", group: "recours", milestone: true, title: "Décision prise" },
    ];
    return [...prefecture, ...ministry, ...recours];
  }

  function getStatusGroupLabel(etape, statusCode) {
    const labels = {
      prefecture: "Préfecture",
      sdanf: "SDANF",
      scec: "SCEC",
      decret: "Décret",
      publication: "Décret",
      final: "Décision",
      recours: "Recours",
    };
    // Étape 13 est partagée entre les groupes "final" et "recours" : on
    // désambiguïse à partir du code de statut pour éviter de préfixer une
    // décision défavorable / recours avec le libellé "Décision".
    if (statusCode && isNegativeDecisionStatus(statusCode)) {
      return labels.recours;
    }
    const group = STEP_GROUPS.find((entry) => entry.etapes.includes(etape));
    return group ? labels[group.key] || group.label : null;
  }

  const NEGATIVE_DECISION_STATUS_CODES = new Set([
    "decision_negative_en_delais_recours",
    "decision_notifiee",
    "demande_en_cours_rapo",
    "controle_demande_notifiee",
    "irrecevabilite_manifeste",
    "irrecevabilite_manifeste_en_delais_recours",
    "css_en_delais_recours",
    "css_notifie",
  ]);

  const RECOURS_OPEN_STATUS_CODES = new Set([
    "decision_negative_en_delais_recours",
    "irrecevabilite_manifeste_en_delais_recours",
    "css_en_delais_recours",
  ]);

  const RECOURS_FINAL_STATUS_CODES = new Set([
    "decision_notifiee",
    "controle_demande_notifiee",
    "irrecevabilite_manifeste",
    "css_notifie",
  ]);

  function normalizeStatusCode(statusCode) {
    return String(statusCode || "").trim().toLowerCase();
  }

  function isNegativeDecisionStatus(statusCode) {
    return NEGATIVE_DECISION_STATUS_CODES.has(normalizeStatusCode(statusCode));
  }

  function isFinalRecoursStatus(statusCode) {
    return RECOURS_FINAL_STATUS_CODES.has(normalizeStatusCode(statusCode));
  }

  function getStepIndexByKey(stepKey) {
    return TRACKING_STEPS.findIndex((step) => step.key === stepKey);
  }

  function inferRecoursTrackingIndex(statusCode) {
    const code = normalizeStatusCode(statusCode);
    if (isFinalRecoursStatus(code)) {
      return getStepIndexByKey("recours_decision_prise");
    }
    if (!RECOURS_OPEN_STATUS_CODES.has(code)) {
      return getStepIndexByKey("recours_statut_courant");
    }
    return getStepIndexByKey("recours_envoye");
  }

  function inferTrackingIndex(statusCode) {
    const code = normalizeStatusCode(statusCode);
    if (!code || code === "-" || code === "code_non_reconnu") return 0;

    if (isNegativeDecisionStatus(code)) {
      return inferRecoursTrackingIndex(code);
    }

    const STATUS_STEP_ALIASES = {
      decret_naturalisation_publie_jo: "decret_naturalisation_publie",
      decret_publie: "decret_naturalisation_publie",
    };
    const aliasedCode = STATUS_STEP_ALIASES[code] || code;
    const exactIndex = TRACKING_STEPS.findIndex((step) => step.code === aliasedCode);
    if (exactIndex >= 0) return exactIndex;

    const info = STATUTS[code];
    if (!info) {
      if (code.startsWith("scec_") || code === "non_applicable") {
        return TRACKING_STEPS.findIndex((step) => step.code === "controle_en_attente_pec");
      }
      return 1;
    }

    let bestIndex = 0;
    TRACKING_STEPS.forEach((step, index) => {
      const stepInfo = step.code ? STATUTS[step.code] : null;
      if (stepInfo && stepInfo.rang <= info.rang) {
        bestIndex = index;
        return;
      }
      if (!stepInfo && step.etape && step.etape <= info.etape) {
        bestIndex = index;
      }
    });
    return bestIndex;
  }

  function getNextMilestoneIndex(steps, milestoneIndex) {
    for (let i = milestoneIndex + 1; i < steps.length; i++) {
      if (steps[i].milestone) return i;
    }
    return steps.length;
  }

  function getMilestoneState(milestoneIndex, currentIndex, steps) {
    const nextMilestone = getNextMilestoneIndex(steps, milestoneIndex);
    if (currentIndex >= nextMilestone) return "done";
    if (currentIndex >= milestoneIndex) return "current";
    return "pending";
  }

  function formatTrackingStepTitle(step, apiInfos = null) {
    if (step.dynamicTitle && apiInfos) {
      const code = normalizeStatusCode(apiInfos.statutCode);
      return STATUTS[code]?.explication || apiInfos.statutDescription || step.title;
    }
    return step.title;
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function getStatusLongDescription(statusCode) {
    const code = String(statusCode || "").trim().toLowerCase();
    return STATUTS[code]?.description || "";
  }

  const TRACKING_STEPS = buildTrackingSteps();

  const prefectureEndIndex = TRACKING_STEPS.findLastIndex((step) => step.group === "prefecture");
  const ministryEndIndex = TRACKING_STEPS.findLastIndex(
    (step) => !["prefecture", "recours"].includes(step.group)
  );
  const recoursStartIndex = TRACKING_STEPS.findIndex((step) => step.group === "recours");
  const recoursEndIndex = TRACKING_STEPS.findLastIndex((step) => step.group === "recours");
  const PREFECTURE_MACRO_PHASE = {
      key: "prefecture",
      title: STEP_GROUPS.find((group) => group.key === "prefecture").label,
      subtitle: STEP_GROUPS.find((group) => group.key === "prefecture").subtitle,
      startIndex: 0,
      endIndex: prefectureEndIndex,
  };
  const MINISTRY_MACRO_PHASE = {
      key: "ministere",
      title: "SDANF & SCEC",
      subtitle: "Contrôles SDANF, validation SCEC, décret et publication",
      startIndex: prefectureEndIndex + 1,
      endIndex: ministryEndIndex,
  };
  const RECOURS_MACRO_PHASE = {
      key: "recours",
      title: "Recours",
      subtitle: "Décision défavorable, RAPO et issue du recours",
      startIndex: recoursStartIndex,
      endIndex: recoursEndIndex,
  };

  function getMacroPhases(statusCode) {
    return [
      PREFECTURE_MACRO_PHASE,
      isNegativeDecisionStatus(statusCode) ? RECOURS_MACRO_PHASE : MINISTRY_MACRO_PHASE,
    ];
  }



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

  function getMacroProgressPct(currentIndex, macroPhases) {
    const clamp = (value) => Math.max(0, Math.min(100, Math.round(value)));
    const firstPhase = macroPhases[0];
    const secondPhase = macroPhases[1];
    const firstPhaseSteps = firstPhase.endIndex - firstPhase.startIndex + 1;
    const secondPhaseSteps = secondPhase.endIndex - secondPhase.startIndex + 1;

    if (currentIndex < secondPhase.startIndex) {
      if (firstPhaseSteps <= 0) return 0;
      const firstPhaseProgress = Math.min(
        currentIndex - firstPhase.startIndex + 1,
        firstPhaseSteps
      );
      return clamp((firstPhaseProgress / firstPhaseSteps) * 50);
    }

    if (secondPhaseSteps <= 0) return 50;
    const secondPhaseProgress = Math.min(
      currentIndex - secondPhase.startIndex + 1,
      secondPhaseSteps
    );
    return clamp(50 + (secondPhaseProgress / secondPhaseSteps) * 50);
  }

  function createMacroStatusIcon(state) {
    const icon = document.createElement("span");
    icon.className = `anf-macro-status-icon is-${state}`;
    icon.innerHTML = MACRO_STATUS_ICONS[state] || MACRO_STATUS_ICONS.pending;
    icon.setAttribute("aria-hidden", "true");
    return icon;
  }

  function getStepState(step, index, currentIndex) {
    if (step.milestone) {
      return getMilestoneState(index, currentIndex, TRACKING_STEPS);
    }
    if (index < currentIndex) return "done";
    if (index === currentIndex) return "current";
    return "pending";
  }

  function shouldShowStepInStepper(step, index, currentIndex, phase) {
    if (step.platform && index < currentIndex) return false;
    if (phase.key === "ministere" && !step.milestone && index !== currentIndex) {
      return false;
    }
    return true;
  }

  function buildTrackStepItem(step, index, currentIndex, apiInfos, railMeta = {}) {
    const {
      isFirst = false,
      isLast = false,
      lineInDone = false,
      lineOutDone = false,
      lineInDuration = null,
      lineInDurationIsStatus = false,
    } = railMeta;
    const state = getStepState(step, index, currentIndex);
    const item = document.createElement("div");
    item.className = `anf-track-step is-${state}`;
    if (lineInDuration) item.classList.add("has-duration");
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
    node.appendChild(createStepIcon(step));

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
      if (lineInDurationIsStatus) {
        durationEl.classList.add("is-status-time");
      } else if (lineInDone) {
        durationEl.classList.add("is-done");
      }
      durationEl.textContent = lineInDuration;
      track.appendChild(durationEl);
    }

    const copy = document.createElement("div");
    copy.className = "anf-step-copy";

    const title = document.createElement("p");
    title.className = "anf-track-step-title";
    title.textContent = formatTrackingStepTitle(step, apiInfos);
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

    const phaseSteps = TRACKING_STEPS.slice(
      phase.startIndex,
      phase.endIndex + 1
    );
    const visibleSteps = phaseSteps
      .map((step, offset) => ({ step, index: phase.startIndex + offset }))
      .filter(({ step, index }) =>
        shouldShowStepInStepper(step, index, currentIndex, phase)
      );

    visibleSteps.forEach(({ step, index }, visibleOffset) => {
      const isFirst = visibleOffset === 0;
      const isLast = visibleOffset === visibleSteps.length - 1;
      const prev = !isFirst ? visibleSteps[visibleOffset - 1] : null;
      let lineInDuration = null;
      let lineInDurationIsStatus = false;
      if (prev) {
        if (index === currentIndex && apiInfos.dateStatut) {
          lineInDuration = formatDurationBetween(
            parseAnchorDate(apiInfos.dateStatut),
            new Date()
          );
          lineInDurationIsStatus = Boolean(lineInDuration);
        } else {
          lineInDuration = getDurationBetweenSteps(
            prev.step,
            prev.index,
            step,
            index,
            currentIndex,
            apiInfos
          );
        }
      }

      stepper.appendChild(
        buildTrackStepItem(step, index, currentIndex, apiInfos, {
          isFirst,
          isLast,
          lineInDone: !isFirst && index <= currentIndex,
          lineOutDone: !isLast && index < currentIndex,
          lineInDuration,
          lineInDurationIsStatus,
        })
      );
    });
    stepperWrap.appendChild(stepper);
    content.appendChild(stepperWrap);

    inner.appendChild(content);
    block.appendChild(inner);
    return block;
  }

  function createStepIcon(step) {
    const stepKey = step.key;
    const iconByStep = {
      demande_envoyee: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M22 2 11 13"></path><path d="m22 2-7 20-4-9-9-4 20-7Z"></path></svg>`,
      examen_pieces: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 0 1-9 9 8.7 8.7 0 0 1-6-2.4"></path><path d="M3 12a9 9 0 0 1 15-6.7"></path><path d="M18 3v5h-5"></path><path d="M6 21v-5h5"></path></svg>`,
      demande_deposee: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v1"></path><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7H3"></path></svg>`,
      dossier_depose: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v1"></path><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7H3"></path></svg>`,
      traitement_plateforme_1: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      recepisse_completude: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"></path><path d="M14 2v6h6"></path><path d="M8 13h8"></path><path d="M8 17h6"></path></svg>`,
      traitement_plateforme_2: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      entretien_assimilation: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4Z"></path><path d="M8 9h8"></path><path d="M8 13h5"></path></svg>`,
      compte_rendu_assimilation: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"></path><path d="M14 2v6h6"></path><path d="m9 15 2 2 4-4"></path></svg>`,
      traitement_plateforme_3: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"></path><path d="M15 5l4 4"></path></svg>`,
      decision_prefecture: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      traitement_sdanf_1: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      traitement_scec: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>`,
      traitement_sdanf_2: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="m16 8 4 4-4 4"></path></svg>`,
      decision_prise: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2Z"></path><path d="m22 6-10 7L2 6"></path></svg>`,
      decret_naturalisation_publie: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path><line x1="4" x2="4" y1="22" y2="15"></line></svg>`,
      ceremonie_naturalisation: `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"></rect><circle cx="8.5" cy="10" r="2"></circle><path d="M6 16c.7-1.4 1.5-2 2.5-2s1.8.6 2.5 2"></path><path d="M14 9h4"></path><path d="M14 13h4"></path><path d="M14 17h3"></path></svg>`,
      demande_en_cours_rapo: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"></path><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"></path><path d="M7 21h10"></path><path d="M12 3v18"></path><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"></path></svg>`,
      recours_envoye: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M22 2 11 13"></path><path d="m22 2-7 20-4-9-9-4 20-7Z"></path></svg>`,
      recours_statut_courant: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"></path><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"></path><path d="M7 21h10"></path><path d="M12 3v18"></path><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"></path></svg>`,
      recours_decision_prise: `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2Z"></path><path d="m22 6-10 7L2 6"></path></svg>`,
    };
    const iconByGroup = {
      sdanf: "traitement_sdanf_1",
      scec: "traitement_scec",
      decret: "traitement_sdanf_2",
      publication: "decision_prise",
      final: "ceremonie_naturalisation",
      recours: "demande_en_cours_rapo",
    };

    const icon = document.createElement("span");
    icon.className = "anf-track-step-icon";
    icon.innerHTML =
      iconByStep[stepKey] ||
      iconByStep[iconByGroup[step.group]] ||
      iconByStep.traitement_plateforme_1;
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
        width: 100%;
        font-family: inherit;
        background: #f8f8fc;
        border-bottom: 1px solid var(--anf-line);
      }
      #anf-extension-stepper-root .anf-stepper-inner {
        position: relative;
        width: 100%;
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
        align-items: flex-start;
        gap: 8px;
        margin-bottom: 4px;
        color: var(--anf-muted);
        font-size: 10px;
      }
      .anf-track-progress-copy {
        display: flex;
        flex-direction: column;
        gap: 3px;
        flex: 1;
        min-width: 0;
      }
      .anf-track-progress-copy > span {
        min-width: 0;
        overflow-wrap: anywhere;
      }
      .anf-track-progress-desc {
        margin: 0;
        color: var(--anf-ink);
        font-size: 10px;
        line-height: 1.4;
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
        width: 100%;
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
        max-width: 100%;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: thin;
        scrollbar-color: #c5c5d8 transparent;
      }
      .anf-phase-stepper-wrap::-webkit-scrollbar {
        height: 6px;
      }
      .anf-phase-stepper-wrap::-webkit-scrollbar-track {
        background: transparent;
      }
      .anf-phase-stepper-wrap::-webkit-scrollbar-thumb {
        background: #c5c5d8;
        border-radius: 999px;
      }
      .anf-phase-stepper-wrap::-webkit-scrollbar-thumb:hover {
        background: #a5a5c0;
      }
      .anf-phase-stepper {
        display: flex;
        align-items: flex-start;
        justify-content: center;
        flex: 0 1 auto;
        width: fit-content;
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
        max-width: 96px;
        padding: 1px 5px;
        border-radius: 4px;
        background: #f0f0f8;
        box-shadow: 0 0 0 2px var(--anf-surface);
        color: #5c5c78;
        font-size: 8.5px;
        font-weight: 700;
        line-height: 1.2;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        pointer-events: none;
      }
      .anf-step-duration.is-done {
        background: #eef0ff;
        color: #3b3b9e;
      }
      .anf-step-duration.is-status-time {
        background: rgba(225, 0, 15, 0.06);
        color: var(--anf-rouge);
        font-weight: 600;
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
        overflow-wrap: anywhere;
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
        overflow-wrap: anywhere;
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
      @media (max-width: 900px) {
        #anf-extension-stepper-root .anf-stepper-inner {
          padding: 9px 10px 11px;
        }
        .anf-macro-block-inner {
          gap: 12px;
          padding: 14px;
          border-radius: 10px;
        }
        .anf-phase-stepper {
          justify-content: flex-start;
        }
        .anf-phase-stepper .anf-track-step {
          flex-basis: 128px;
          width: 128px;
          min-width: 104px;
          max-width: 140px;
        }
      }
      @media (max-width: 640px) {
        #anf-extension-stepper-root .anf-stepper-inner {
          padding: 8px 8px 10px;
        }
        .anf-track-progress-meta {
          flex-direction: column;
          align-items: stretch;
          gap: 5px;
        }
        .anf-track-progress-meta > span:last-child {
          align-self: flex-start;
        }
        .anf-macro-block-inner {
          flex-direction: column;
          gap: 12px;
          padding: 12px;
          border-width: 1px;
        }
        .anf-macro-head {
          align-items: flex-start;
        }
        .anf-macro-badge {
          padding: 3px 8px;
          font-size: 9px;
        }
        .anf-macro-subtitle {
          margin-bottom: 10px;
        }
        .anf-macro-status-icon {
          flex: 0 0 40px;
          width: 40px;
          height: 40px;
        }
        .anf-macro-title { font-size: 15px; }
        .anf-phase-stepper-wrap {
          display: block;
          overflow-x: visible;
        }
        .anf-phase-stepper {
          display: flex;
          flex-direction: column;
          align-items: stretch;
          width: 100%;
          max-width: none;
          padding: 4px 0 0;
        }
        .anf-phase-stepper .anf-track-step {
          position: relative;
          flex: 0 0 auto;
          width: 100%;
          min-width: 0;
          max-width: none;
          display: grid;
          grid-template-columns: 32px minmax(0, 1fr);
          column-gap: 10px;
          padding: 0 0 12px;
        }
        .anf-phase-stepper .anf-track-step:last-child {
          padding-bottom: 0;
        }
        .anf-step-track {
          grid-column: 1;
          grid-row: 1;
          align-self: stretch;
          justify-content: center;
          width: 32px;
          height: auto;
          min-height: 46px;
          flex-direction: column;
        }
        .anf-step-line {
          width: 2px;
          min-width: 0;
          height: auto;
          min-height: 8px;
          flex: 1 1 0;
        }
        .anf-step-node {
          flex: 0 0 30px;
          width: 30px;
          height: 30px;
        }
        .anf-step-copy {
          grid-column: 2;
          grid-row: 1;
          align-items: flex-start;
          min-width: 0;
          padding: 3px 0 0;
          text-align: left;
        }
        .anf-track-step.has-duration .anf-step-copy {
          padding-top: 17px;
        }
        .anf-track-step.is-current .anf-step-copy {
          padding: 7px 8px;
          margin-top: -3px;
        }
        .anf-track-step.is-current.has-duration .anf-step-copy {
          padding-top: 21px;
        }
        .anf-track-step-icon svg {
          width: 14px;
          height: 14px;
        }
        .anf-track-step-title {
          font-size: 10px;
          text-align: left;
        }
        .anf-track-step.is-current .anf-track-step-title {
          font-size: 10.5px;
        }
        .anf-track-step-detail {
          font-size: 9px;
          text-align: left;
        }
        .anf-track-masked-row {
          align-self: flex-start;
          justify-content: flex-start;
        }
        .anf-track-step-detail.is-status-card,
        .anf-track-step-detail.is-decret-card {
          padding: 5px;
        }
        .anf-step-duration {
          left: 42px;
          top: 1px;
          transform: none;
          max-width: calc(100vw - 96px);
          overflow: hidden;
          text-overflow: ellipsis;
          font-size: 7.5px;
          padding: 1px 3px;
        }
      }
      @media (prefers-reduced-motion: reduce) {
        #anf-extension-stepper-root *,
        #anf-extension-stepper-root *::before,
        #anf-extension-stepper-root *::after {
          animation-duration: 0.001ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.001ms !important;
          scroll-behavior: auto !important;
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
      dateStatut,
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
    if (stepKey === "demande_deposee" || stepKey === "dossier_depose") {
      if (anchorRawDate) {
        details.push({ text: formatDate(anchorRawDate), variant: "date" });
      }
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
    if (isCurrent && !["decret_naturalisation_publie", "ceremonie_naturalisation", "decision_prise"].includes(stepKey)) {
      details.push({ text: dossierStatus, variant: "status-card" });
    }
    if (
      stepKey === "decret_naturalisation_publie" ||
      stepKey === "ceremonie_naturalisation" ||
      stepKey === "decision_prise"
    ) {
      if (isCurrent) {
        details.push({ text: dossierStatus, variant: "status-card" });
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

    const inferredIndex = inferTrackingIndex(apiInfos.statutCode);
    const ceremonyStepIndex = TRACKING_STEPS.findIndex(
      (step) => step.key === "ceremonie_naturalisation"
    );
    const isNegativeStatus = isNegativeDecisionStatus(apiInfos.statutCode);
    let currentIndex = inferredIndex;
    if (
      apiInfos.decretId &&
      ceremonyStepIndex >= 0 &&
      !isNegativeStatus
    ) {
      currentIndex = Math.max(inferredIndex, ceremonyStepIndex);
    }
    currentIndex = Math.min(TRACKING_STEPS.length - 1, currentIndex);

    let root = document.getElementById("anf-extension-stepper-root");
    if (!root) {
      root = document.createElement("section");
      root.id = "anf-extension-stepper-root";
      header.insertAdjacentElement("afterend", root);
    }

    const macroPhases = getMacroPhases(apiInfos.statutCode);
    const progressPct = getMacroProgressPct(currentIndex, macroPhases);
    const currentStep = TRACKING_STEPS[currentIndex];
    const currentStepTitle = currentStep ? formatTrackingStepTitle(currentStep, apiInfos) : "";
    const longDescription = getStatusLongDescription(apiInfos.statutCode);
    const currentPhase =
      macroPhases.find(
        (phase) =>
          currentIndex >= phase.startIndex && currentIndex <= phase.endIndex
      ) || macroPhases[macroPhases.length - 1];

    root.innerHTML = `
      <div class="anf-stepper-inner">
        <div class="anf-track-head">
          <h2 class="anf-track-title">Demande d'accès à la Nationalité Française</h2>
        </div>
        <div class="anf-track-progress-wrap">
          <div class="anf-track-progress-meta">
            <div class="anf-track-progress-copy">
              <span><strong>${currentPhase.title}</strong> · ${escapeHtml(currentStepTitle)}</span>
                          ${longDescription ? `<p class="anf-track-progress-desc">${escapeHtml(longDescription)}</p>` : ""}

              </div>
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
    macroPhases.forEach((phase, phaseIndex) => {
      trackFragment.appendChild(
        buildMacroPhaseBlock(phase, currentIndex, apiInfos)
      );
      if (phaseIndex < macroPhases.length - 1) {
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

    const scrollBehavior = prefersReducedMotion() ? "auto" : "smooth";

    requestAnimationFrame(() => {
      const currentStepEl = list.querySelector(".anf-track-step.is-current");
      if (currentStepEl) {
        currentStepEl.scrollIntoView({
          behavior: scrollBehavior,
          block: "nearest",
          inline: "center",
        });
      } else {
        const currentBlock = list.querySelector(".anf-macro-block.is-current");
        if (currentBlock) {
          currentBlock.scrollIntoView({
            behavior: scrollBehavior,
            block: "nearest",
          });
        }
      }
    });

    console.log(
      `Extension API Naturalisation : stepper injecté (${currentIndex + 1}/${TRACKING_STEPS.length})`
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