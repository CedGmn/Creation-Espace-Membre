<?php


$bdd = new PDO("mysql:host=localhost;dbname=espacemembre","root","AzfagGG150.");

$results["error"] = false;
$results["message"] = [];

if(isset($_POST)){
	
	if (!empty($_POST['pseudo']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST["password2"])){

		
		$pseudo = $_POST['pseudo'];
		$email = $_POST['email'];
		$password = $_POST['password'];
		$password2 = $_POST['password2'];

 			 
 			 //verification pseudo
		if (strlen($pseudo) < 2 || !preg_match("/^[a-zA-Z0-9_-]+$/", $pseudo) || strlen($pseudo) > 60){
			
			$results['error'] = true;
			$results['message']["pseudo"] = "Pseudo invalide";

		}else{
			//verifier que le pseudo n'existe pas
			$requete = $db->prepare("SELECT id FROM users WHERE pseudo = :pseudo");
			$requete->execute([':pseudo' => $pseudo]);

			$row = $requete->fetch();

			if ($row){

				$results['error'] = true;
			    $results['message']["pseudo"] = "Pseudo deja utilisé";
			}

		}
		//vérification email
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)){

			$results["error"] = true;
			$results['message']['email'] = "Email invalide";
		}else{
			//verifier que l'email n'existe pas
			$requete = $db->prepare("SELECT id FROM users WHERE email = :email");
			$requete->execute([':email' => $email]);

			$row = $requete->fetch();

			if ($row) {

				$results['error'] = true;
			    $results['message']["email"] = "email deja utilisé";
			}
		}

		//verification du password
		if ($password !== $password2) {

			$results["error"] = true;
			$results['message']['password'] = "les mots de passes doivent etre identique";
		}

		if ($results["error"] == false) {

			$password = password_hash($password, PASSWORD_BCRYPT);

			//insertion
			$sql = $db->prepare("INSERT INTO users(pseudo, email, password) VALUES(:pseudo, :email, :password)");

				$sql->execute([":pseudo" => $pseudo, ":email" => $email, ":password" => $password]);

				if (!$sql) {
					$results["error"] = true;
					$results["message"] = "Erreur d'inscription";
				}
		}
		
	}else{
		$results["error"] = true;
		$results["message"] = "veuillez remplir tous les champs";
	}

	echo json_encode($results);
}
?>