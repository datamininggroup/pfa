package test.scala.makedocs

import scala.language.postfixOps

import org.junit.runner.RunWith

import org.scalatest.FlatSpec
import org.scalatest.junit.JUnitRunner
import org.scalatest.Matchers

import org.scoringengine.pfa.signature.Sig
import org.scoringengine.pfa.signature.Sigs
import org.scoringengine.pfa.lib1
import test.scala._

@RunWith(classOf[JUnitRunner])
class MakeDocsSuite extends FlatSpec with Matchers {
  val libfcn =
    lib1.array.provides ++
    lib1.bytes.provides ++
    lib1.core.provides ++
    lib1.enum.provides ++
    lib1.fixed.provides ++
    lib1.impute.provides ++
    lib1.map.provides ++
    lib1.math.provides ++
    lib1.record.provides ++
    lib1.string.provides ++
    lib1.stat.sample.provides ++
    lib1.model.tree.provides

  "LaTeX generator" must "generate LaTeX" taggedAs(MakeDocsLatex) in {
    val outputFile = new java.io.PrintWriter(new java.io.File("doc/spec/libfcns.tex"))

    outputFile.println("\\" + """usepackage{xstring}

\newcommand{\libfcn}[1]{%
    \par\noindent%
    \IfEqCase*{#1}{%""")

    for ((n, f) <- libfcn) {
      val sanitized = f.name.replace("%", "\\%").replace("&", "\\&").replace("^", "\\^{}")

      val asname = sanitized.replace("~", "TILDE")
      val quoted = "\"" + sanitized.replace("~", "\\textasciitilde{}") + "\""

      outputFile.print(s"    {${asname}}{\\noindent")

      var where = Seq[String]()

      f.sig match {
        case Sig(params, ret) => {
          val names = params map {case (n, p) => n} mkString(", ")
          outputFile.print(s"\\mbox{\\tt \\{${quoted}:\\ [${names}]\\}")

          for ((n, p) <- params) {
            val pp = p.toString.replace("_", "\\_")
            where = where :+ s" & \\tt ${n} \\rm & ${pp} \\\\"
          }
          where = where :+ s" & & $$\\to$$ ${ret} \\\\"
        }
        case Sigs(sigs) => {
          outputFile.print(s"\\mbox{\\tt")

          val possibilities =
            for (Sig(params, ret) <- sigs) yield {
              val names = params map {case (n, p) => n} mkString(", ")

              s"\\{${quoted}:\\ [${names}]\\}"
            }

          outputFile.print(possibilities.distinct.mkString(" \\rm or \\tt "))

          val newwhere =
            (for (Sig(params, ret) <- sigs) yield {
              (for ((n, p) <- params) yield {
                val pp = p.toString.replace("_", "\\_")
                s" & \\tt ${n} \\rm & ${pp} \\\\"
              }).mkString(" ") + s" & & $$\\to$$ ${ret} \\\\"
            }).mkString(" \\end{tabular} \\\\ or \\\\ \\begin{tabular}{p{0.01\\linewidth} l p{0.8\\linewidth}}")
          where = where :+ newwhere
        }
      }

      outputFile.print("} \\\\");

      if (!where.isEmpty) {
        outputFile.print("\\rm \\begin{tabular}{p{0.01\\linewidth} l p{0.8\\linewidth}}" + where.mkString(" ") + " \\end{tabular}")
      }

      outputFile.println("}%");
    }

    outputFile.println("""    }[{\bf FIXME: LaTeX error: wrong libfcn name!}]%
}%""")
    outputFile.close()

  }

}
