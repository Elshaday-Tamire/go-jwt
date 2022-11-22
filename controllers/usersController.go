package controllers

import (
	"go-jwt/initializers"
	"go-jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {

	var body struct {
		Username    string
		Password    string
		PhoneNumber string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})

		return
	}

	// Create the user
	user := models.User{Username: body.Username, Password: string(hash), Phonenumber: body.PhoneNumber}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})

		return
	}
	//Respond
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
	})
}

func Login(c *gin.Context) {
	//Get the email and pass of req body
	var body struct {
		Username string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}
	//Look up requested user
	var user models.User
	initializers.DB.First(&user, "username =?", body.Username)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid username or password",
		})
		return
	}

	//Compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid username or password",
		})
		return
	}

	// Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	//send it back
	//c.SetSameSite(http.SameSiteLaxMode)
	//c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	type Dictionary map[string]interface{}
	data := []Dictionary{
		{
			"user": []Dictionary{
				{"fullName": "REGASA ALEMU CHALI", "email": "abc@gmail.com", "photo": "http://10.1.245.150:7080/im.images/signatures/IM406389.jpg", "phone": "919584347", "address": "Addis Ababa, Ethiopia"},
			},
		},
		{

			"accounts": []Dictionary{
				{"account no": "1000089352733", "balance": "10", "opening date": "", "product": "Saving Account", "statment": []Dictionary{
					{"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"},
				}},
				{"account no": "1000089352733", "balance": "10", "opening date": "", "product": "Saving Account", "statment": []Dictionary{
					{"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"}, {"TXNREF": "FT22181023T3\\BNK", "CRAMT": "0.00", "DRAMT": "0.00", "DATE": "30 JUN 2022", "DESC": "Transfer"},
				}},
			},
		},
	}
	if user.Phonenumber == "919584347" {
		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"token":    tokenString,
			"response": data,
		})
	}
	if user.Phonenumber != "919584347" {
		c.JSON(http.StatusOK, gin.H{
			"status": "failure",
			//"token":    tokenString,
			"response": "no data found",
		})
	}

}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	//user.(models.User).Username
	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func CheckPhone(c *gin.Context) {
	//read body
	var reqbody struct {
		Phonenumber string
	}
	c.Bind(&reqbody)
	// 	httpposturl := "http://10.1.245.150:7080/v1/cbo/"
	// 	var jsonData = []byte(fmt.Sprintf(`{
	// 		"CRM_PhoneRequest": {
	// 	  "ESBHeader": {
	// 		  "serviceCode": "790000",
	// 		  "channel": "USSD",
	// 		  "Service_name":"CRM_PhoneRequest",
	// 		  "Message_Id": "6255726662"
	// 	  },
	// 	  "WebRequestCommon": {
	// 		  "company": "",
	// 		  "password": "123456",
	// 		  "userName": "CRMUSER"
	// 	  },
	// 	  "CRMType": [
	// 		  {
	// 			  "columnName": "@ID",
	// 			  "criteriaValue": "%s",
	// 			  "operand": "EQ"
	// 		  }
	// 	  ]
	//   }
	//   }`, reqbody.Phonenumber))
	// 	request, error := http.NewRequest("POST", httpposturl, bytes.NewBuffer(jsonData))
	// 	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	// 	client := &http.Client{}
	// 	response, error := client.Do(request)
	// 	if error != nil {
	// 		panic(error)
	// 	}
	// 	defer response.Body.Close()

	// 	fmt.Println("response Status:", response.Status)
	// 	fmt.Println("response Headers:", response.Header)
	// 	// read response body

	// 	body, error := ioutil.ReadAll(response.Body)
	// 	x := map[string]string{}
	// 	json.Unmarshal(body, &x)
	// 	if error != nil {
	// 		fmt.Println(error)
	// 	}
	// 	// close response body
	// 	response.Body.Close()

	// 	// print response body
	// 	fmt.Println(x)

	if reqbody.Phonenumber != "919584347" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "Cutomer does not exist",
		})
		return
	}
	//respond
	c.JSON(http.StatusOK, gin.H{
		"fullName": "REGASA ALEMU CHALI",
		"status":   "success",
	})
}
