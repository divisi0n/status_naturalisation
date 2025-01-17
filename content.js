(async function () {
  const CONFIG = {
    URL_PATTERN: "administration-etrangers-en-france",
    TAB_NAME: "Demande d'accès à la Nationalité Française",
    API_ENDPOINT:
      "https://administration-etrangers-en-france.interieur.gouv.fr/api/anf/dossier-stepper",
    WAIT_TIME: 100,
  };

  //dedicaced to Kamal weld 93
  function IamKamal_23071993(encryptedString) {
    const kfal =
      "U2FsdGVkX1+WsXvmnkAtjZT0iM2BfCGU9y76DrRufAVcmcIYgKDITp7wjJgXP2p+";

    function getSarout() {
      return CryptoJS.AES.decrypt(kfal, "Sg-164342").toString(
        CryptoJS.enc.Utf8
      );
    }

    function getCurrentDate() {
      var i = new Intl.DateTimeFormat("fr-CA", {
        timeZone: "Africa/Casablanca",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour12: false,
      }).format(new Date());

      return i;
    }

    function generateSHA256Sarout(e) {
      return CryptoJS.SHA256(e).toString(CryptoJS.enc.Hex);
    }

    function generateSarout(t) {
      var i = generateSHA256Sarout(getSarout()) + t;
      return generateSHA256Sarout(i);
    }

    function xorEncryptDecrypt(t, r) {
      var c = CryptoJS.enc.Utf8.parse(t);
      var a = CryptoJS.enc.Utf8.parse(r);
      var u = c.clone();
      for (var s = 0; s < c.sigBytes; s++) {
        u.words[s] ^= a.words[s % a.sigBytes];
      }
      console.log(
        "CryptoJS.enc.Utf8.stringify(u): " + CryptoJS.enc.Utf8.stringify(u)
      );

      return CryptoJS.enc.Utf8.stringify(u);
    }

    var r = getCurrentDate();
    var i = generateSarout(r);
    return xorEncryptDecrypt(encryptedString, i);
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

    const tabElement = await waitForElement();
    tabElement.click();

    // Get dossier data directly
    const response = await fetch(CONFIG.API_ENDPOINT);
    if (!response.ok) throw new Error(`Erreur API: ${response.status}`);

    const dossierData = await response.json();
    if (!dossierData?.dossier?.statut) throw new Error("Statut non trouvé");

    const data = {
      dossier: dossierData.dossier,
    };

    // Fonction pour obtenir la description du statut
    function getStatusDescription(status) {
      const statusMap = {
        // 1 Dépôt de la demande
        dossier_depose: "Dossier déposé, attendez changement d'API",
        // 2 Examen des pièces en cours
        verification_formelle_a_traiter: "Préfecture a reçu, tri en cours",
        verification_formelle_en_cours:
          "Préfecture examine rapidement votre demande",
        verification_formelle_mise_en_demeure:
          "Préfecture : Possible demande de compléments pour dossier",
        css_mise_en_demeure_a_affecter:
          "Préfecture : Mise en demeure attribuée",
        css_mise_en_demeure_a_rediger: "Préfecture : Mise en demeure à rédiger",
        instruction_a_affecter: "Préfecture termine tri, attente d'agent",
        // 3 Réception du récépissé de complétude
        instruction_recepisse_completude_a_envoyer:
          "Préfecture : Lecture détaillée par agent commencée",
        instruction_recepisse_completude_a_envoyer_retour_complement_a_traiter:
          "Préfecture : Compléments ou entretien possibles avec agent",
        // 4 Entretien
        instruction_date_ea_a_fixer:
          "Préfecture : Demande complète, récépissé reçu, enquêtes lancées",
        ea_demande_report_ea:
          "Préfecture : Report possible, compléments encore possibles",
        ea_en_attente_ea:
          "Préfecture : Attente convocation entretien réglementaire",
        ea_crea_a_valider:
          "Préfecture : Entretien passé, compte-rendu à rédiger",
        // 5 Traitement en cours
        prop_decision_pref_a_effectuer:
          "Préfecture doit statuer sur naturalisation",
        prop_decision_pref_en_attente_retour_hierarchique:
          "Préfecture : Décision préfectorale en discussion hiérarchique",
        prop_decision_pref_prop_a_editer:
          "Préfecture : Décision prise, rédaction en cours",
        prop_decision_pref_en_attente_retour_signataire:
          "Préfecture : Décision au préfet pour signature",
        // 6 Traitement en cours
        controle_a_affecter: "SDANF : Dossier transmis, attente d'affectation",
        controle_a_effectuer:
          "SDANF : Ministère contrôle dossier, attend état civil",
        controle_en_attente_pec: "SCEC : Attente de pièce d'état civil",
        controle_pec_a_faire: "SCEC : Pièce d'état civil en cours",
        controle_transmise_pour_decret:
          "SDANF : Décret transmis pour approbation",
        controle_en_attente_retour_hierarchique:
          "SDANF : Attente retour hiérarchique pour décret",
        controle_decision_a_editer:
          "SDANF : Décision hiérarchique prise, édition prochaine",
        controle_en_attente_signature:
          "SDANF : Décision prise, attente signature",
        // 7 Traitement en cours
        transmis_a_ac: "Décret : Dossier transmis au service décret",
        a_verifier_avant_insertion_decret:
          "Décret : Vérification avant insertion décret",
        prete_pour_insertion_decret:
          "Décret : Dossier prêt pour insertion décret",
        decret_publie: "Décret de naturalisation publié",
        decret_envoye_prefecture: "Décret envoyé à préfecture",
        notification_envoyee: "Décret : Notification envoyée au demandeur",
        demande_traitee: "Décret : Demande finalisée",
        // 8 Décision
        decret_naturalisation_publie:
          "Décision : Décret de naturalisation publié",
        decret_en_preparation: "Décision : Décret en préparation",
        decret_a_qualifier: "Décision : Décret à qualifier",
        decret_en_validation: "Décision : Décret en validation",
        css_en_delais_recours: "Décision : CSS en délais de recours",
        decision_negative_en_delais_recours:
          "Décision négative en délais de recours",
        irrecevabilite_manifeste: "Décision : irrecevabilité manifeste",
        decision_notifiee: "Décision notifiée",
        css_notifie: "Décision : CSS notitie",
        demande_en_cours_rapo: "Décision : Demande en cours RAPO",
        controle_demande_notifiee: "Décision : Contrôle demande notifiée",
        DECRET_PUBLIE: "Décision : Décret publié",
        // 9
        code_non_reconnu: "Code non reconnu",
      };

      return statusMap[status] || statusMap["code_non_reconnu"];
    }

    const dossierStatus = getStatusDescription(
      IamKamal_23071993(data.dossier.statut).toLowerCase()
    );

    // Fonction pour calculer le nombre de jours écoulés
    function daysAgo(dateString) {
      const inputDate = new Date(dateString);
      const currentDate = new Date();
      const diffInDays = Math.floor(
        (currentDate - inputDate) / (1000 * 60 * 60 * 24)
      );

      if (diffInDays === 0) return "Aujourd'hui";
      if (diffInDays === 1) return "Il y a 1 jr";
      if (diffInDays <= 30) return `Il y a ${diffInDays} jrs`;

      const years = Math.floor(diffInDays / 365);
      const months = Math.floor((diffInDays % 365) / 30);

      if (years >= 1) {
        if (months === 0) {
          return `Il y a ${years} ${years === 1 ? "an" : "ans"}`;
        }
        return `Il y a ${years} ${
          years === 1 ? "an" : "ans"
        } et ${months} mois`;
      }

      return `Il y a ${months} mois`;
    }

    const activeStep = document.querySelector("li.itemFrise.active");
    if (!activeStep) throw new Error("Étape active non trouvée");

    // Trouver la classe CSS dynamique
    const dynamicClass = activeStep
      .getAttributeNames()
      .find((name) => name.startsWith("_ngcontent-"));

    // Création du nouvel élément avec le style et le format spécifiés
    const newElement = document.createElement("li");
    newElement.setAttribute(dynamicClass, "");
    newElement.className = "itemFrise active ng-star-inserted";
    newElement.setAttribute(
      "style",
      `
      background: linear-gradient(165deg, #dbe2e9, #ffffff);
      border: 2px solid #255a99;
      border-radius: 8px;
      box-shadow: inset 2px 2px 5px rgba(0, 0, 0, 0.2), 5px 5px 15px rgba(0, 0, 0, 0.3);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: Arial, sans-serif;
      font-size: 18px;
      color: #080000;
    `
    );
    newElement.innerHTML = `
      <div ${dynamicClass} class="itemFriseContent">
        <span ${dynamicClass} class="itemFriseIcon">
          <span ${dynamicClass} aria-hidden="true" class="fa fa-hourglass-start" style="color:  #bf2626!important;"></span>
        </span>
        <p ${dynamicClass}>
          ${dossierStatus} <span style="color: #bf2626;">(${daysAgo(
      data?.dossier?.date_statut
    )})</span>
        </p>
      </div>
    `;

    activeStep.parentNode.insertBefore(newElement, activeStep.nextSibling);
    console.log("Nouvel élément inséré avec le statut du dossier");
  } catch (error) {
    console.error("Erreur d'initialisation:", error);
  }
})();
