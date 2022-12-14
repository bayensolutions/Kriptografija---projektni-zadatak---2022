import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

public class Quiz {
    public static String QUESTIONS_PATH = ".\\questions\\";
    public static String IMAGES_PATH = ".\\images\\";

    public static int[] arrayNumbers = new int[20];
    public static int serialNumber = 0;
    public static int correctAnswersCounter=0;

    public static void hideQuestions() {

        List<String> questions = null;
        try {
            questions = Files.readAllLines(Paths.get(QUESTIONS_PATH + "pitanja.txt"));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        int number = 0;
        for (String question : questions) {
            number++;
            System.out.println(number);
            System.out.println(question);
            Steganography.encode(new File(IMAGES_PATH + number + ".png"), question,
                    new File(QUESTIONS_PATH + number + ".png"));
        }
    }

    public static String showQuestion(int number) {
        String[] array = Steganography.decode(new File(QUESTIONS_PATH + (number + 1) + ".png")).split("#");
        String rightAnswer = null;
        System.out.println(array[0]);
        if (number < 10) {
            showAnswers(array);
            rightAnswer = array[5];
        } else {
            rightAnswer = array[1];
        }
        return rightAnswer;
    }

    private static void showAnswers(String[] array) {

        List<Integer> list = Arrays.asList(1, 2, 3, 4);
        Collections.shuffle(list);
        System.out.println(list.get(0));
        System.out.println(list.get(1));
        System.out.println(list.get(2));
        System.out.println(list.get(3));

        System.out.println("A) " + array[list.get(0)]);
        System.out.println("B) " + array[list.get(1)]);
        System.out.println("C) " + array[list.get(2)]);
        System.out.println("D) " + array[list.get(3)]);
    }

    public void startQuiz(String user) {
        System.out.println("DOBRO DOSLI NA KVIZ. SRECNO!");
        for (int i = 0; i < 5; i++) {
            selectQuestion();
        }

        exportResults(user,correctAnswersCounter);
        correctAnswersCounter=0;
        serialNumber=0;
        for(int number=0;number<20;number++){
            arrayNumbers[number]=0;
        }
    }

    public static void selectQuestion() {
        int number = (int) (Math.random() * 20);
        Scanner scanner = new Scanner(System.in);
        String answer = null;
        if (arrayNumbers[number] == 0) {
            System.out.println(++serialNumber + ". pitanje: ");
            arrayNumbers[number] = 1;
            String rightAnswer = showQuestion(number);
            if (number < 10) {
                System.out.println("Vas odgovor [izaberite 1 od 4 odgovora - A B C D] ");
                scanner = new Scanner(System.in);
                answer = scanner.nextLine();
            } else {
                System.out.println("Vas odgovor: [Unesite odgovor]");
                scanner = new Scanner(System.in);
                answer = scanner.nextLine();
            }
            if (rightAnswer.equals(answer)) {
                System.out.println("Tacan odgovor!");
                correctAnswersCounter++;
            } else {
                System.out.println("Netacan odgovor!");
            }
        } else {
            selectQuestion();
        }
    }

    public void exportResults(String user,int correctAnswers) {
        try {
            Files.write(Paths.get("results.txt"), (user+"\t"+LocalDateTime.now()+"\t"+correctAnswers).getBytes(), StandardOpenOption.APPEND);
            System.out.println("Uspjesan ispis.");
          } catch (IOException e) {
            System.out.println("Neuspjesan ispis.");
            e.printStackTrace();
          }
    }

}
